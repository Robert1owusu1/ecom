// FILE LOCATION: backend/server.js
import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import session from 'express-session';
import passport from 'passport';
import { configurePassport } from './config/passPort.js';

// Database
import pool from './config/db.js';
import initDatabase from './config/initdatabase.js';

// Middleware
import { 
  setupSecurity, 
  sanitizeInput, 
  preventSQLInjection 
} from './midleware/securityMiddleware.js';
import { 
  apiLimiter, 
  authLimiter, 
  uploadLimiter, 
  orderLimiter
  // ✅ REMOVED: passwordResetLimiter (not used yet)
} from './midleware/rateLimitMiddleware.js';
import { errorHandeler, notFound } from './midleware/errorMidleware.js';

// Routes
import productRoutes from './routes/productRoutes.js';
import userRoutes from './routes/userRoutes.js';
import orderRoutes from './routes/orderRoutes.js';
import paymentRoutes from './routes/paymentRoutes.js';
import uploadRoutes from './routes/uploadRoute.js';
import settingRoutes from './routes/settingRoutes.js';
import profileRoutes from './routes/profileRoutes.js';
import authRoutes from './routes/authRoutes.js';
import { startCleanupSchedule } from './utils/cleanupJobs.js';

// Setup __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const port = process.env.PORT || 5000;

// ============================================
// DATABASE CONNECTION & INITIALIZATION
// ============================================
const initializeDatabase = async () => {
  try {
    const connection = await pool.getConnection();
    console.log('✅ MySQL Connection Established');
    connection.release();
    
    console.log('🔄 Initializing database tables...');
    await initDatabase();
    console.log('✅ Database tables initialized successfully');
    
  } catch (err) {
    console.error('❌ Database initialization failed:', err.message);
    throw err;
  }
};

// ============================================
// EXPRESS APP INITIALIZATION
// ============================================
const app = express();

// ✅ CRITICAL: Enable trust proxy for Railway/Heroku/Vercel
// This MUST be set BEFORE any middleware that uses req.ip
app.set('trust proxy', 1);

// ============================================
// MIDDLEWARE (ORDER IS CRITICAL!)
// ============================================

// 1. Enable gzip compression for responses
app.use(compression());

// 2. Setup security middleware - CORS, Helmet, HPP
setupSecurity(app);

// 3. Cookie Parser - MUST be before authentication
app.use(cookieParser());

// 4. Session middleware (required for OAuth flow)
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true, // Prevent XSS attacks
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax' // CSRF protection
  }
}));

// 5. Initialize Passport for OAuth
app.use(passport.initialize());
app.use(passport.session());
configurePassport();

// 6. Upload routes with rate limiting - MUST come BEFORE body parsers
app.use('/api/upload', uploadLimiter, uploadRoutes);

// 7. Body parser middleware - applied AFTER upload routes
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// 8. Serve static files from uploads directory
const uploadsPath = path.join(__dirname, 'uploads');
app.use('/uploads', express.static(uploadsPath));

// 9. Apply input sanitization to ALL routes (XSS protection)
app.use(sanitizeInput);

// 10. Apply SQL injection prevention to API routes
app.use('/api/', preventSQLInjection);

// 11. Apply general rate limiting to all API routes
app.use('/api/', apiLimiter);

// ============================================
// ROUTES
// ============================================

// Health check endpoint (no rate limiting)
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK',
    database: 'MySQL',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: {
      used: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
      total: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`
    }
  });
});

// Root route
app.get('/', (req, res) => {
  res.send('API is running...');
});

// API Routes with specific rate limiters
app.use('/api/products', productRoutes);
app.use('/api/users', userRoutes);
app.use('/api/orders', orderLimiter, orderRoutes); // ✅ Order-specific rate limiting
app.use('/api/payments', paymentRoutes);
app.use('/api/settings', settingRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/auth', authLimiter, authRoutes); // ✅ Auth-specific rate limiting

// ============================================
// ERROR HANDLING - Must be LAST
// ============================================

app.use(notFound);
app.use(errorHandeler);

// ============================================
// START SERVER WITH DATABASE INITIALIZATION
// ============================================

const startServer = async () => {
  try {
    // Initialize database first
    await initializeDatabase();
    
    // Start cleanup jobs
    startCleanupSchedule();
    console.log('✅ Cleanup scheduler started');
    
    // Start the server
    const server = app.listen(port, () => {
      console.log('='.repeat(50));
      console.log(`✅ Server running in ${process.env.NODE_ENV || 'development'} mode`);
      console.log(`🚀 Server listening on port ${port}`);
      
      // Show Railway URL if available
      const publicUrl = process.env.RAILWAY_PUBLIC_DOMAIN 
        ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
        : `http://localhost:${port}`;
      
      console.log(`🌐 API: ${publicUrl}`);
      console.log(`❤️  Health: ${publicUrl}/health`);
      console.log('='.repeat(50));
      console.log('🔐 Security:');
      console.log('   - CORS enabled');
      console.log('   - Helmet (XSS, HSTS, CSP)');
      console.log('   - HPP protection');
      console.log('   - Rate limiting');
      console.log('   - SQL injection prevention');
      console.log('   - Input sanitization');
      console.log('   - Trust proxy enabled');
      console.log('='.repeat(50));
    });

    // ============================================
    // GRACEFUL SHUTDOWN HANDLERS
    // ============================================

    process.on('unhandledRejection', (err) => {
      console.error('🚨 Unhandled Promise Rejection:', err.message);
      console.error(err.stack);
      server.close(() => {
        console.log('💤 Server closed due to unhandled rejection');
        process.exit(1);
      });
    });

    process.on('uncaughtException', (err) => {
      console.error('🚨 Uncaught Exception:', err.message);
      console.error(err.stack);
      process.exit(1);
    });

    process.on('SIGTERM', () => {
      console.log('👋 SIGTERM received, closing server gracefully...');
      server.close(() => {
        console.log('💤 Server closed');
        process.exit(0);
      });
    });

  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
startServer();

export default app;