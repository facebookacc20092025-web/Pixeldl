require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const winston = require('winston');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

// Platform detection
const PLATFORM = process.env.PLATFORM || 
                 (process.env.RENDER ? 'render' : 
                  process.env.RAILWAY ? 'railway' : 
                  process.env.HEROKU ? 'heroku' : 
                  process.env.VERCEL ? 'vercel' : 'unknown');

// Platform-specific timeout configurations
const PLATFORM_CONFIG = {
  render: {
    requestTimeout: 25000,
    heartbeatInterval: 10000,
    maxDirectSize: 50 * 1024 * 1024 // 50MB
  },
  railway: {
    requestTimeout: 30000,
    heartbeatInterval: 10000,
    maxDirectSize: 50 * 1024 * 1024
  },
  heroku: {
    requestTimeout: 30000,
    heartbeatInterval: 15000,
    maxDirectSize: 30 * 1024 * 1024
  },
  vercel: {
    requestTimeout: 10000, // Vercel has very short timeouts
    heartbeatInterval: 5000,
    maxDirectSize: 10 * 1024 * 1024
  },
  unknown: {
    requestTimeout: 60000,
    heartbeatInterval: 30000,
    maxDirectSize: 100 * 1024 * 1024
  }
};

const config = PLATFORM_CONFIG[PLATFORM] || PLATFORM_CONFIG.unknown;

// Configure logging
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss'
    }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    new winston.transports.File({ 
      filename: 'logs/combined.log',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Ensure logs directory exists
if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

// Streaming metrics
const streamingMetrics = {
  activeStreams: 0,
  totalStreams: 0,
  totalBytes: 0,
  failedStreams: 0,
  platform: PLATFORM
};

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || 'default-secret-key-change-me';

// Create persistent HTTP agents for better performance
const httpAgent = new http.Agent({ 
  keepAlive: true,
  keepAliveMsecs: 1000,
  maxFreeSockets: 256,
  timeout: 60000
});

const httpsAgent = new https.Agent({ 
  keepAlive: true,
  keepAliveMsecs: 1000,
  maxFreeSockets: 256,
  timeout: 60000
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CORS configuration
const corsOptions = {
  origin: '*',
  methods: ['GET', 'HEAD', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Range'],
  exposedHeaders: ['Content-Length', 'Content-Type', 'Content-Disposition', 'Accept-Ranges', 'Content-Range']
};
app.use(cors(corsOptions));

// Compression (for non-stream responses)
app.use(compression({
  filter: (req, res) => {
    // Don't compress streaming responses
    return !req.path.includes('/api/proxy/stream') && compression.filter(req, res);
  }
}));

// HTTP request logging
app.use(morgan('combined', { 
  stream: fs.createWriteStream(path.join(__dirname, 'logs/access.log'), { flags: 'a' })
}));
app.use(morgan('dev'));

// Rate limiting - more generous for streaming
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.RATE_LIMIT_MAX || 50, // Lower limit for streaming
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  skip: (req) => {
    // Skip rate limiting for streaming requests (they're long-lived)
    return req.path.includes('/api/proxy/stream');
  },
  keyGenerator: (req) => req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress
});
app.use('/api/', limiter);

// Create browser instance with persistent agents
const createBrowserInstance = () => {
  return axios.create({
    headers: {
      'User-Agent': process.env.USER_AGENT || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
      'Cache-Control': 'no-cache',
      'Pragma': 'no-cache',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Sec-Fetch-User': '?1',
      'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
      'Sec-Ch-Ua-Mobile': '?0',
      'Sec-Ch-Ua-Platform': '"Windows"',
      'DNT': '1'
    },
    httpAgent,
    httpsAgent,
    timeout: parseInt(process.env.REQUEST_TIMEOUT) || config.requestTimeout,
    maxRedirects: 5,
    decompress: true,
    maxContentLength: Infinity,
    maxBodyLength: Infinity
  });
};

// Headers to forward from original response
const FORWARD_HEADERS = [
  'content-type',
  'content-length',
  'content-disposition',
  'accept-ranges',
  'content-range',
  'last-modified',
  'etag',
  'cache-control',
  'expires'
];

// Validate URL function
const isValidUrl = (urlString) => {
  try {
    const url = new URL(urlString);
    const allowedHosts = process.env.ALLOWED_DOMAINS ? 
      process.env.ALLOWED_DOMAINS.split(',') : 
      ['pixeldrain.com', 'pixeldrain.eu'];
    
    // Check if hostname is allowed
    const isAllowed = allowedHosts.some(domain => 
      url.hostname === domain || url.hostname.endsWith(`.${domain}`)
    );
    
    // Check protocol
    const isHttp = url.protocol === 'http:' || url.protocol === 'https:';
    
    return isAllowed && isHttp;
  } catch (err) {
    return false;
  }
};

// Extract filename from headers
const extractFilename = (headers) => {
  const contentDisposition = headers['content-disposition'];
  if (contentDisposition) {
    const match = contentDisposition.match(/filename\*?=["']?(?:UTF-\d['"]*)?([^;"']+)["']?/i) ||
                  contentDisposition.match(/filename=["']?([^;"']+)["']?/i);
    if (match && match[1]) {
      return decodeURIComponent(match[1].trim());
    }
  }
  
  // Fallback: extract from URL
  const url = headers['x-original-url'] || '';
  if (url) {
    try {
      const urlObj = new URL(url);
      const pathname = urlObj.pathname;
      const filename = pathname.split('/').pop();
      if (filename && filename.includes('.')) {
        return filename;
      }
    } catch (e) {
      // Invalid URL, continue
    }
  }
  
  return 'downloaded_file';
};

// Check if file size is too large for platform
const isFileTooLarge = async (url, browser) => {
  try {
    const headResponse = await browser.head(url, { timeout: 10000 });
    const contentLength = headResponse.headers['content-length'];
    
    if (contentLength) {
      const fileSize = parseInt(contentLength, 10);
      return fileSize > config.maxDirectSize;
    }
    return false;
  } catch (error) {
    logger.warn('Could not determine file size', { url, error: error.message });
    return false;
  }
};

// Generate heartbeat data (simple whitespace that won't affect the stream)
const generateHeartbeat = () => {
  // Return a single space character
  return ' ';
};

// Main proxy endpoint with platform-aware streaming
app.get('/api/proxy/stream', async (req, res) => {
  const startTime = Date.now();
  const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  let heartbeatInterval = null;
  let streamPaused = false;
  let bytesTransferred = 0;
  
  // Increment active streams
  streamingMetrics.activeStreams++;
  streamingMetrics.totalStreams++;
  
  const cleanup = () => {
    if (heartbeatInterval) {
      clearInterval(heartbeatInterval);
      heartbeatInterval = null;
    }
    streamingMetrics.activeStreams--;
  };
  
  try {
    const { url, apiKey, filename: customFilename, disableHeartbeat } = req.query;
    
    // Log request
    logger.info(`[${requestId}] Request started`, { 
      platform: PLATFORM,
      url: url ? url.substring(0, 100) : 'empty',
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      range: req.headers.range
    });
    
    // API Key validation
    if (API_KEY !== 'default-secret-key-change-me' && apiKey !== API_KEY) {
      logger.warn(`[${requestId}] Unauthorized access attempt`);
      cleanup();
      return res.status(401).json({ 
        error: 'Unauthorized',
        message: 'Invalid API key' 
      });
    }
    
    // URL validation
    if (!url) {
      logger.warn(`[${requestId}] Missing URL parameter`);
      cleanup();
      return res.status(400).json({ 
        error: 'Bad Request',
        message: 'URL parameter is required' 
      });
    }
    
    if (!isValidUrl(url)) {
      logger.warn(`[${requestId}] Invalid or not allowed URL`, { url });
      cleanup();
      return res.status(400).json({ 
        error: 'Bad Request',
        message: 'Invalid URL or domain not allowed' 
      });
    }
    
    // Prepare URLs for Pixeldrain
    let viewUrl = url;
    let downloadUrl = url;
    
    try {
      const urlObj = new URL(url);
      if (urlObj.hostname.includes('pixeldrain.com') || urlObj.hostname.includes('pixeldrain.eu')) {
        const fileId = urlObj.pathname.split('/').pop();
        if (fileId && fileId.match(/^[a-zA-Z0-9]+$/)) {
          viewUrl = `https://pixeldrain.com/u/${fileId}`;
          downloadUrl = `https://pixeldrain.com/api/file/${fileId}?download`;
          logger.debug(`[${requestId}] Pixeldrain detected`, { fileId, viewUrl, downloadUrl });
        }
      }
    } catch (err) {
      logger.error(`[${requestId}] URL parsing error`, { error: err.message });
    }
    
    const browser = createBrowserInstance();
    
    // Check if file is too large for platform
    const tooLarge = await isFileTooLarge(downloadUrl, browser);
    if (tooLarge && PLATFORM !== 'unknown') {
      logger.warn(`[${requestId}] File too large for platform`, { platform: PLATFORM });
      cleanup();
      return res.status(413).json({
        error: 'File Too Large',
        message: `This platform (${PLATFORM}) cannot handle files larger than ${Math.round(config.maxDirectSize / 1024 / 1024)}MB`,
        code: 'FILE_TOO_LARGE',
        maxSize: config.maxDirectSize,
        platform: PLATFORM
      });
    }
    
    // Step 1: Get initial cookies and session
    logger.info(`[${requestId}] Visiting page to get cookies`, { viewUrl });
    
    const pageResponse = await browser.get(viewUrl, {
      timeout: 15000,
      validateStatus: (status) => status < 400
    }).catch(err => {
      logger.error(`[${requestId}] Page visit failed`, { error: err.message });
      throw err;
    });
    
    // Extract cookies
    let cookieString = '';
    if (pageResponse.headers['set-cookie']) {
      const cookies = pageResponse.headers['set-cookie'].map(c => {
        const cookie = c.split(';')[0];
        return cookie.includes('=') ? cookie : '';
      }).filter(Boolean);
      cookieString = cookies.join('; ');
      logger.debug(`[${requestId}] Cookies extracted`, { count: cookies.length });
    }
    
    // Handle range requests
    const requestHeaders = {
      ...browser.defaults.headers.common,
      'Referer': viewUrl,
      'Cookie': cookieString,
      'Sec-Fetch-Dest': 'empty',
      'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Site': 'same-origin',
      'Origin': new URL(viewUrl).origin,
      'X-Requested-With': 'XMLHttpRequest'
    };
    
    // Forward range header if present
    if (req.headers.range) {
      requestHeaders['Range'] = req.headers.range;
    }
    
    // Step 2: Stream the file
    logger.info(`[${requestId}] Starting file stream`, { 
      downloadUrl,
      platform: PLATFORM,
      timeout: config.requestTimeout
    });
    
    const streamResponse = await axios({
      method: 'GET',
      url: downloadUrl,
      responseType: 'stream',
      headers: requestHeaders,
      httpAgent,
      httpsAgent,
      timeout: config.requestTimeout - 2000, // Leave buffer
      maxRedirects: 3,
      decompress: true
    }).catch(err => {
      logger.error(`[${requestId}] Stream request failed`, { error: err.message });
      throw err;
    });
    
    // Check if response is valid
    if (!streamResponse || !streamResponse.data) {
      throw new Error('Invalid response from target server');
    }
    
    // Determine filename
    const filename = customFilename || extractFilename({
      ...streamResponse.headers,
      'x-original-url': url
    });
    
    // Set response headers
    res.setHeader('X-Request-ID', requestId);
    res.setHeader('X-Proxy-Server', 'VPS-Stream-Proxy/2.0');
    res.setHeader('X-Platform', PLATFORM);
    res.setHeader('Access-Control-Expose-Headers', '*');
    
    // For streaming responses, use chunked transfer encoding
    res.setHeader('Transfer-Encoding', 'chunked');
    res.setHeader('Connection', 'keep-alive');
    
    // Don't set content-length for streaming
    if (!req.headers.range) {
      delete streamResponse.headers['content-length'];
    }
    
    // Forward important headers
    FORWARD_HEADERS.forEach(header => {
      if (streamResponse.headers[header]) {
        res.setHeader(header, streamResponse.headers[header]);
      }
    });
    
    // Set appropriate status code
    if (streamResponse.status === 206) {
      res.status(206); // Partial Content
    } else if (streamResponse.status === 200 && req.headers.range) {
      res.status(206); // We're serving partial content
    } else {
      res.status(streamResponse.status || 200);
    }
    
    // Always set Content-Disposition for file download
    if (!res.getHeader('content-disposition')) {
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
    }
    
    logger.info(`[${requestId}] Streaming started`, { 
      filename,
      contentType: streamResponse.headers['content-type'],
      contentLength: streamResponse.headers['content-length'],
      range: req.headers.range,
      platform: PLATFORM
    });
    
    // Send headers immediately
    res.flushHeaders();
    
    // Setup heartbeat for platforms with short timeouts
    if (disableHeartbeat !== 'true' && PLATFORM !== 'unknown') {
      heartbeatInterval = setInterval(() => {
        try {
          if (res.writable && !res.finished && !res.destroyed) {
            res.write(generateHeartbeat());
            res.flush();
          } else {
            clearInterval(heartbeatInterval);
            heartbeatInterval = null;
          }
        } catch (err) {
          clearInterval(heartbeatInterval);
          heartbeatInterval = null;
        }
      }, config.heartbeatInterval);
    }
    
    // Buffer control to prevent memory issues
    const MAX_BUFFER_SIZE = 2 * 1024 * 1024; // 2MB buffer
    
    // Pipe the stream with backpressure control
    streamResponse.data.on('data', (chunk) => {
      bytesTransferred += chunk.length;
      
      // Implement backpressure control
      if (res.writableLength > MAX_BUFFER_SIZE && !streamPaused) {
        streamResponse.data.pause();
        streamPaused = true;
        logger.debug(`[${requestId}] Source stream paused due to backpressure`);
      }
    });
    
    // Resume when buffer drains
    res.on('drain', () => {
      if (streamPaused) {
        streamResponse.data.resume();
        streamPaused = false;
        logger.debug(`[${requestId}] Source stream resumed`);
      }
    });
    
    // Handle stream completion
    streamResponse.data.on('end', () => {
      const duration = Date.now() - startTime;
      streamingMetrics.totalBytes += bytesTransferred;
      
      logger.info(`[${requestId}] Stream completed`, {
        bytesTransferred,
        duration: `${duration}ms`,
        speed: duration > 0 ? `${(bytesTransferred / duration * 1000 / 1024 / 1024).toFixed(2)} MB/s` : 'N/A',
        platform: PLATFORM
      });
      
      cleanup();
      res.end();
    });
    
    // Handle stream errors
    streamResponse.data.on('error', (error) => {
      streamingMetrics.failedStreams++;
      
      logger.error(`[${requestId}] Stream error`, { 
        error: error.message,
        bytesTransferred,
        platform: PLATFORM
      });
      
      cleanup();
      
      if (!res.headersSent) {
        res.status(500).json({ 
          error: 'Stream error',
          message: 'Error while streaming content',
          platform: PLATFORM
        });
      } else {
        res.destroy();
      }
    });
    
    // Handle client disconnect
    req.on('close', () => {
      logger.info(`[${requestId}] Client disconnected`, { 
        bytesTransferred,
        platform: PLATFORM
      });
      
      cleanup();
      streamResponse.data.destroy();
    });
    
    // Platform-specific timeout handling
    if (PLATFORM !== 'unknown') {
      // Set timeout slightly less than platform timeout
      res.setTimeout(config.requestTimeout - 5000, () => {
        logger.warn(`[${requestId}] Platform timeout approaching, closing connection`, {
          platform: PLATFORM,
          timeout: config.requestTimeout
        });
        
        cleanup();
        streamResponse.data.destroy();
        
        if (!res.headersSent) {
          res.status(504).json({
            error: 'Platform Timeout',
            message: `Stream terminated due to ${PLATFORM} platform timeout limits`,
            platform: PLATFORM,
            maxDuration: `${config.requestTimeout}ms`
          });
        }
      });
    }
    
    // Start piping the stream
    streamResponse.data.pipe(res);
    
  } catch (error) {
    const duration = Date.now() - startTime;
    streamingMetrics.failedStreams++;
    
    logger.error(`[${requestId}] Request failed`, {
      error: error.message,
      stack: error.stack,
      duration: `${duration}ms`,
      platform: PLATFORM
    });
    
    cleanup();
    
    if (!res.headersSent) {
      if (error.response) {
        const status = error.response.status;
        const message = error.response.data?.message || error.message;
        
        if (status === 403 || status === 429) {
          res.status(403).json({ 
            error: 'Access Denied',
            message: 'The target server is blocking requests. This IP might be blacklisted.',
            code: 'BLOCKED_BY_TARGET',
            platform: PLATFORM
          });
        } else if (status === 404) {
          res.status(404).json({
            error: 'Not Found',
            message: 'The requested file was not found on the target server.',
            platform: PLATFORM
          });
        } else {
          res.status(status).json({ 
            error: 'Proxy Error',
            message,
            status,
            platform: PLATFORM
          });
        }
      } else if (error.code === 'ECONNABORTED') {
        res.status(504).json({ 
          error: 'Timeout',
          message: `Request to target server timed out (${config.requestTimeout}ms)`,
          platform: PLATFORM
        });
      } else if (error.code === 'ENOTFOUND') {
        res.status(502).json({ 
          error: 'Bad Gateway',
          message: 'Cannot resolve target server hostname',
          platform: PLATFORM
        });
      } else if (error.code === 'ECONNREFUSED') {
        res.status(502).json({
          error: 'Bad Gateway',
          message: 'Connection refused by target server',
          platform: PLATFORM
        });
      } else {
        res.status(500).json({ 
          error: 'Internal Server Error',
          message: error.message,
          platform: PLATFORM
        });
      }
    }
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    platform: PLATFORM,
    config: {
      requestTimeout: config.requestTimeout,
      heartbeatInterval: config.heartbeatInterval,
      maxDirectSize: config.maxDirectSize
    },
    metrics: streamingMetrics
  };
  
  // Check if we're close to memory limits (for platform awareness)
  const memoryUsage = process.memoryUsage();
  const maxMemory = parseInt(process.env.AVAILABLE_MEMORY) || 512 * 1024 * 1024; // Default 512MB
  const memoryPercent = (memoryUsage.heapUsed / maxMemory) * 100;
  
  if (memoryPercent > 80) {
    health.status = 'warning';
    health.memoryWarning = `Memory usage high: ${memoryPercent.toFixed(1)}%`;
  }
  
  res.json(health);
});

// Metrics endpoint
app.get('/metrics', (req, res) => {
  res.json({
    ...streamingMetrics,
    memory: process.memoryUsage(),
    uptime: process.uptime(),
    platform: PLATFORM,
    config,
    timestamp: new Date().toISOString()
  });
});

// Platform info endpoint
app.get('/platform', (req, res) => {
  res.json({
    platform: PLATFORM,
    config,
    limitations: {
      maxFileSize: `${Math.round(config.maxDirectSize / 1024 / 1024)}MB`,
      timeout: `${config.requestTimeout}ms`,
      heartbeat: `${config.heartbeatInterval}ms`
    },
    recommendations: PLATFORM === 'unknown' ? 
      'Running on custom server, no platform limitations' :
      `Running on ${PLATFORM.toUpperCase()}. Large files may need alternative handling.`
  });
});

// Info endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'VPS Stream Proxy Server',
    version: '2.0.0',
    platform: PLATFORM,
    endpoints: {
      proxy: '/api/proxy/stream?url=<encoded_url>&apiKey=<your_key>[&disableHeartbeat=true]',
      health: '/health',
      metrics: '/metrics',
      platform: '/platform',
      usage: 'Send GET request with URL parameter to proxy'
    },
    status: 'operational',
    limitations: PLATFORM === 'unknown' ? 'None (custom server)' : 
      `Platform: ${PLATFORM}, Max file: ${Math.round(config.maxDirectSize / 1024 / 1024)}MB, Timeout: ${config.requestTimeout}ms`
  });
});

// Handle 404
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Not Found',
    message: `Cannot ${req.method} ${req.path}`,
    platform: PLATFORM
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { 
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    platform: PLATFORM
  });
  
  if (!res.headersSent) {
    res.status(500).json({ 
      error: 'Internal Server Error',
      message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message,
      platform: PLATFORM
    });
  }
});

// Start server with platform awareness
const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info(`VPS Proxy Server started`, {
    port: PORT,
    platform: PLATFORM,
    nodeVersion: process.version,
    environment: process.env.NODE_ENV || 'development',
    pid: process.pid,
    config: {
      requestTimeout: config.requestTimeout,
      maxDirectSize: `${Math.round(config.maxDirectSize / 1024 / 1024)}MB`
    }
  });
  
  console.log(`
  ╔══════════════════════════════════════════════════╗
  ║   VPS Proxy Server v2.0                         ║
  ║   Platform: ${PLATFORM.padEnd(27)}║
  ║   Listening on port ${PORT}                         ║
  ║   Environment: ${(process.env.NODE_ENV || 'development').padEnd(24)}║
  ║   Timeout: ${config.requestTimeout}ms                          ║
  ║   Max File: ${Math.round(config.maxDirectSize / 1024 / 1024)}MB                          ║
  ╚══════════════════════════════════════════════════╝
  `);
});

// Platform-specific server tuning
if (PLATFORM !== 'unknown') {
  // Reduce server timeout for platforms
  server.keepAliveTimeout = 5000; // 5 seconds
  server.headersTimeout = 10000; // 10 seconds
  
  logger.info(`Platform-specific tuning applied`, {
    keepAliveTimeout: server.keepAliveTimeout,
    headersTimeout: server.headersTimeout
  });
}

// Graceful shutdown
const shutdown = (signal) => {
  logger.info(`Received ${signal}, shutting down gracefully...`, {
    activeStreams: streamingMetrics.activeStreams,
    platform: PLATFORM
  });
  
  // Stop accepting new connections
  server.close(() => {
    logger.info('Server closed', { platform: PLATFORM });
    process.exit(0);
  });
  
  // Force shutdown after delay
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down', {
      platform: PLATFORM
    });
    process.exit(1);
  }, 15000);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', { 
    error: error.message, 
    stack: error.stack,
    platform: PLATFORM
  });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { 
    reason: reason?.message || reason,
    platform: PLATFORM
  });
});

// Periodic metrics logging
setInterval(() => {
  logger.debug('Streaming metrics', { ...streamingMetrics });
}, 60000); // Every minute
