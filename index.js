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

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || 'default-secret-key-change-me';

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // Disable for API server
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CORS configuration
const corsOptions = {
  origin: '*', // Change this to specific domains in production
  methods: ['GET', 'HEAD', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Length', 'Content-Type', 'Content-Disposition']
};
app.use(cors(corsOptions));

// Compression (for non-stream responses)
app.use(compression());

// HTTP request logging
app.use(morgan('combined', { 
  stream: fs.createWriteStream(path.join(__dirname, 'logs/access.log'), { flags: 'a' })
}));
app.use(morgan('dev'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.RATE_LIMIT_MAX || 100, // Limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress
});
app.use('/api/', limiter);

// Create browser instance with realistic headers
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
    timeout: parseInt(process.env.REQUEST_TIMEOUT) || 60000,
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
  'etag'
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
    const urlObj = new URL(url);
    const pathname = urlObj.pathname;
    const filename = pathname.split('/').pop();
    if (filename && filename.includes('.')) {
      return filename;
    }
  }
  
  return 'downloaded_file';
};

// Main proxy endpoint
app.get('/api/proxy/stream', async (req, res) => {
  const startTime = Date.now();
  const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  try {
    const { url, apiKey, filename: customFilename } = req.query;
    
    // Log request
    logger.info(`[${requestId}] Request started`, { 
      url: url ? url.substring(0, 100) : 'empty',
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    // API Key validation
    if (API_KEY !== 'default-secret-key-change-me' && apiKey !== API_KEY) {
      logger.warn(`[${requestId}] Unauthorized access attempt`);
      return res.status(401).json({ 
        error: 'Unauthorized',
        message: 'Invalid API key' 
      });
    }
    
    // URL validation
    if (!url) {
      logger.warn(`[${requestId}] Missing URL parameter`);
      return res.status(400).json({ 
        error: 'Bad Request',
        message: 'URL parameter is required' 
      });
    }
    
    if (!isValidUrl(url)) {
      logger.warn(`[${requestId}] Invalid or not allowed URL`, { url });
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
    
    // Step 1: Get initial cookies and session
    logger.info(`[${requestId}] Visiting page to get cookies`, { viewUrl });
    
    const pageResponse = await browser.get(viewUrl, {
      timeout: 30000,
      validateStatus: (status) => status < 400 // Accept redirects
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
    
    // Step 2: Stream the file
    logger.info(`[${requestId}] Starting file stream`, { downloadUrl });
    
    const streamResponse = await axios({
      method: 'GET',
      url: downloadUrl,
      responseType: 'stream',
      headers: {
        ...browser.defaults.headers.common,
        'Referer': viewUrl,
        'Cookie': cookieString,
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'Origin': new URL(viewUrl).origin,
        'X-Requested-With': 'XMLHttpRequest'
      },
      timeout: 300000, // 5 minutes for large files
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
    res.setHeader('X-Proxy-Server', 'VPS-Stream-Proxy/1.0');
    res.setHeader('Access-Control-Expose-Headers', '*');
    
    // Forward important headers
    FORWARD_HEADERS.forEach(header => {
      if (streamResponse.headers[header]) {
        res.setHeader(header, streamResponse.headers[header]);
      }
    });
    
    // Always set Content-Disposition for file download
    if (!res.getHeader('content-disposition')) {
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
    }
    
    logger.info(`[${requestId}] Streaming started`, { 
      filename,
      contentType: streamResponse.headers['content-type'],
      contentLength: streamResponse.headers['content-length']
    });
    
    // Pipe the stream
    streamResponse.data.pipe(res);
    
    // Track progress
    let bytesTransferred = 0;
    streamResponse.data.on('data', (chunk) => {
      bytesTransferred += chunk.length;
    });
    
    // Handle stream completion
    streamResponse.data.on('end', () => {
      const duration = Date.now() - startTime;
      logger.info(`[${requestId}] Stream completed`, {
        bytesTransferred,
        duration: `${duration}ms`,
        speed: duration > 0 ? `${(bytesTransferred / duration * 1000 / 1024 / 1024).toFixed(2)} MB/s` : 'N/A'
      });
    });
    
    // Handle stream errors
    streamResponse.data.on('error', (error) => {
      logger.error(`[${requestId}] Stream error`, { 
        error: error.message,
        bytesTransferred
      });
      
      if (!res.headersSent) {
        res.status(500).json({ 
          error: 'Stream error',
          message: 'Error while streaming content'
        });
      } else {
        res.destroy();
      }
    });
    
    // Handle client disconnect
    req.on('close', () => {
      streamResponse.data.destroy();
      logger.info(`[${requestId}] Client disconnected`, { bytesTransferred });
    });
    
  } catch (error) {
    const duration = Date.now() - startTime;
    logger.error(`[${requestId}] Request failed`, {
      error: error.message,
      stack: error.stack,
      duration: `${duration}ms`
    });
    
    if (!res.headersSent) {
      if (error.response) {
        const status = error.response.status;
        const message = error.response.data?.message || error.message;
        
        if (status === 403 || status === 429) {
          res.status(403).json({ 
            error: 'Access Denied',
            message: 'The target server is blocking requests. This IP might be blacklisted.',
            code: 'BLOCKED_BY_TARGET'
          });
        } else {
          res.status(status).json({ 
            error: 'Proxy Error',
            message,
            status
          });
        }
      } else if (error.code === 'ECONNABORTED') {
        res.status(504).json({ 
          error: 'Timeout',
          message: 'Request to target server timed out'
        });
      } else if (error.code === 'ENOTFOUND') {
        res.status(502).json({ 
          error: 'Bad Gateway',
          message: 'Cannot resolve target server hostname'
        });
      } else {
        res.status(500).json({ 
          error: 'Internal Server Error',
          message: error.message
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
    env: process.env.NODE_ENV || 'development'
  };
  
  res.json(health);
});

// Info endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'VPS Stream Proxy Server',
    version: '1.0.0',
    endpoints: {
      proxy: '/api/proxy/stream?url=<encoded_url>&apiKey=<your_key>',
      health: '/health',
      usage: 'Send GET request with URL parameter to proxy'
    },
    status: 'operational'
  });
});

// Handle 404
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Not Found',
    message: `Cannot ${req.method} ${req.path}`
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { 
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method
  });
  
  if (!res.headersSent) {
    res.status(500).json({ 
      error: 'Internal Server Error',
      message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message
    });
  }
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info(`VPS Proxy Server started`, {
    port: PORT,
    nodeVersion: process.version,
    environment: process.env.NODE_ENV || 'development',
    pid: process.pid
  });
  
  console.log(`
  ╔══════════════════════════════════════════════╗
  ║   VPS Proxy Server                           ║
  ║   Listening on port ${PORT}                     ║
  ║   Environment: ${process.env.NODE_ENV || 'development'}      ║
  ║   PID: ${process.pid}                              ║
  ╚══════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
const shutdown = (signal) => {
  logger.info(`Received ${signal}, shutting down gracefully...`);
  
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
  
  // Force shutdown after 10 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', { error: error.message, stack: error.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { reason: reason?.message || reason });
});
