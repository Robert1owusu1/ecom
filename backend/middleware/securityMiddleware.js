// FILE LOCATION: middleware/securityMiddleware.js
// DESCRIPTION: Security middleware for headers, XSS, SQL injection protection (MySQL)

import helmet from 'helmet';
import cors from 'cors';
import hpp from 'hpp';

/**
 * Setup all security middleware
 * NOTE: Using MySQL, so no mongoSanitize needed (that's for MongoDB/NoSQL)
 * NOTE: xss-clean removed due to Express 5 compatibility issues
 * @param {Express} app - Express application instance
 */
export const setupSecurity = (app) => {
  // ============================================
  // 1. CORS CONFIGURATION
  // ============================================
  const allowedOrigins = process.env.FRONTEND_URL 
    ? process.env.FRONTEND_URL.split(',').map(url => url.trim())
    : ['http://localhost:3000'];

  console.log('🔐 Allowed CORS origins:', allowedOrigins);

  app.use(cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, Postman, server-to-server)
      if (!origin) {
        console.log('✅ Allowing request with no origin (mobile/Postman)');
        return callback(null, true);
      }
      
      // Check if origin is in whitelist
      if (allowedOrigins.includes(origin)) {
        console.log('✅ Allowing whitelisted origin:', origin);
        return callback(null, true);
      }
      
      // Allow ALL Vercel domains (*.vercel.app) for preview deployments
      if (origin.match(/^https:\/\/.*\.vercel\.app$/)) {
        console.log('✅ Allowing Vercel domain:', origin);
        return callback(null, true);
      }
      
      // Allow localhost in development
      if (process.env.NODE_ENV === 'development' && origin.startsWith('http://localhost')) {
        console.log('✅ Allowing localhost in development:', origin);
        return callback(null, true);
      }
      
      // Reject everything else
      console.warn('❌ CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization'],
    optionsSuccessStatus: 200
  }));

  // ============================================
  // 2. SECURITY HEADERS WITH HELMET
  // ============================================
  // XSS filter is enabled by default in helmet
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:", "blob:"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true
    },
    noSniff: true,
    frameguard: {
      action: 'deny'
    },
    xssFilter: true
  }));

  // ============================================
  // 3. HTTP PARAMETER POLLUTION PREVENTION
  // ============================================
  app.use(hpp({
    whitelist: [
      'page', 
      'limit', 
      'sort', 
      'status', 
      'category',
      'price',
      'rating',
      'search',
      'minPrice',
      'maxPrice',
      'featured',
      'color',
      'size',
      'material'
    ]
  }));

  console.log('✅ Security middleware initialized (CORS, Helmet with XSS, HPP)');
};

/**
 * Input sanitization middleware (replaces xss-clean)
 * This provides XSS protection by escaping dangerous characters
 * Defense-in-depth: Works alongside Helmet's XSS filter
 */
export const sanitizeInput = (req, res, next) => {
  const sanitizeValue = (value) => {
    if (typeof value === 'string') {
      // Remove null bytes
      value = value.replace(/\0/g, '');
      
      // Escape dangerous HTML characters to prevent XSS
      value = value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
      
      // ✅ FIXED: Remove control characters without regex
      // eslint-disable-next-line no-control-regex
      value = value.replace(/[\x00-\x1F\x7F]/g, '');
    }
    return value;
  };

  const sanitizeObject = (obj) => {
    if (!obj || typeof obj !== 'object') return;
    
    Object.keys(obj).forEach(key => {
      if (typeof obj[key] === 'string') {
        obj[key] = sanitizeValue(obj[key]);
      } else if (Array.isArray(obj[key])) {
        obj[key] = obj[key].map(item => 
          typeof item === 'string' ? sanitizeValue(item) : item
        );
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        sanitizeObject(obj[key]);
      }
    });
  };

  // Sanitize all input sources
  if (req.body) {
    sanitizeObject(req.body);
  }

  if (req.query) {
    sanitizeObject(req.query);
  }

  if (req.params) {
    sanitizeObject(req.params);
  }
  
  next();
};

/**
 * SQL injection prevention (additional layer for MySQL)
 * Defense-in-depth: Works alongside parameterized queries
 * NOTE: Always use parameterized queries as primary defense!
 */
export const preventSQLInjection = (req, res, next) => {
  const sqlPatterns = [
    /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|TRUNCATE)\b/gi,
    /(--|;|\/\*|\*\/|xp_|sp_)/gi,
    /['"`]/gi,
    /(\bOR\b|\bAND\b).*[=<>]/gi, // OR/AND with comparison operators
    /INFORMATION_SCHEMA/gi,
    /SLEEP\s*\(/gi,
    /BENCHMARK\s*\(/gi
  ];

  const checkValue = (value) => {
    if (typeof value === 'string') {
      // Allow common search terms but block SQL patterns
      const suspiciousPatterns = sqlPatterns.filter(pattern => 
        pattern.test(value)
      );
      
      if (suspiciousPatterns.length > 0) {
        return true;
      }
    }
    return false;
  };

  const checkObject = (obj, location) => {
    // ✅ FIXED: Use Object.prototype.hasOwnProperty.call instead
    for (let key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        if (checkValue(obj[key])) {
          console.warn(`🚨 Potential SQL injection detected in ${location}.${key}`);
          console.warn(`   Value: ${obj[key]}`);
          return true;
        }
      }
    }
    return false;
  };

  // Check query parameters
  if (req.query && checkObject(req.query, 'query')) {
    return res.status(400).json({ 
      message: 'Invalid input detected',
      code: 'INVALID_INPUT'
    });
  }

  // Check body parameters
  if (req.body && checkObject(req.body, 'body')) {
    return res.status(400).json({ 
      message: 'Invalid input detected',
      code: 'INVALID_INPUT'
    });
  }

  // Check URL parameters
  if (req.params && checkObject(req.params, 'params')) {
    return res.status(400).json({ 
      message: 'Invalid input detected',
      code: 'INVALID_INPUT'
    });
  }

  next();
};