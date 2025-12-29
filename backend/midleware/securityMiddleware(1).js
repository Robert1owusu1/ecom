// FILE: middleware/securityMiddleware.js
import helmet from 'helmet';
import cors from 'cors';
import hpp from 'hpp';
import rateLimit from 'express-rate-limit';

/**
 * Setup all security middleware (PRODUCTION-READY)
 */
export const setupSecurity = (app) => {
  // 1. CORS - Allow only trusted origins
  const allowedOrigins = process.env.FRONTEND_URL 
    ? process.env.FRONTEND_URL.split(',').map(url => url.trim())
    : ['http://localhost:3000'];

  app.use(cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, Postman, server-to-server)
      if (!origin) return callback(null, true);
      
      // Whitelist specific origins
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      
      // Allow Vercel preview deployments
      if (origin.match(/https:\/\/.*\.vercel\.app$/)) {
        return callback(null, true);
      }
      
      // Allow localhost in development
      if (process.env.NODE_ENV === 'development' && origin.startsWith('http://localhost')) {
        return callback(null, true);
      }
      
      // Reject everything else
      console.warn(`🚫 CORS blocked request from: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization']
  }));

  // 2. Security Headers with Helmet
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:", "blob:"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  }));

  // 3. Rate Limiting (prevent brute force/DDoS)
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
  });
  app.use('/api/', limiter);

  // 4. Prevent HTTP Parameter Pollution
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
      'maxPrice'
    ]
  }));

  console.log('✅ Security middleware initialized');
  console.log(`   - CORS: ${allowedOrigins.length} allowed origin(s)`);
  console.log(`   - Helmet: Security headers enabled`);
  console.log(`   - Rate Limiting: 100 req/15min per IP`);
  console.log(`   - HPP: Parameter pollution protection`);
};

/**
 * Input sanitization middleware for XSS protection
 */
export const sanitizeInput = (req, res, next) => {
  const sanitizeValue = (value) => {
    if (typeof value === 'string') {
      // Remove null bytes
      value = value.replace(/\0/g, '');
      
      // Escape dangerous HTML characters (XSS protection)
      value = value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
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
      } else if (typeof obj[key] === 'object') {
        sanitizeObject(obj[key]);
      }
    });
  };

  // Sanitize all inputs
  if (req.body) sanitizeObject(req.body);
  if (req.query) sanitizeObject(req.query);
  if (req.params) sanitizeObject(req.params);
  
  next();
};

/**
 * SQL injection prevention (defense-in-depth)
 * NOTE: Use with parameterized queries, not instead of them!
 */
export const preventSQLInjection = (req, res, next) => {
  const sqlPatterns = [
    /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION)\b/gi,
    /(--|;|\/\*|\*\/|xp_|sp_)/gi,
    /['"`]|\\['"`]/gi 
  ];

  const checkValue = (value) => {
    if (typeof value === 'string') {
      return sqlPatterns.some(pattern => pattern.test(value));
    }
    return false;
  };

  const checkObject = (obj, location) => {
    for (let key in obj) {
      if (checkValue(obj[key])) {
        console.warn(`🚨 Potential SQL injection in ${location}.${key}: ${obj[key]}`);
        return true;
      }
    }
    return false;
  };

  // Check all inputs
  if (req.query && checkObject(req.query, 'query')) {
    return res.status(400).json({ message: 'Invalid input detected' });
  }
  
  if (req.body && checkObject(req.body, 'body')) {
    return res.status(400).json({ message: 'Invalid input detected' });
  }
  
  if (req.params && checkObject(req.params, 'params')) {
    return res.status(400).json({ message: 'Invalid input detected' });
  }

  next();
};