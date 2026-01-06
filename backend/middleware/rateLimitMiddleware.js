// FILE LOCATION: middleware/rateLimitMiddleware.js
// DESCRIPTION: Rate limiting to prevent abuse and DDoS attacks

import rateLimit from 'express-rate-limit';

/**
 * General API rate limiter
 * Applied to all /api/* routes
 */
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per 15 minutes
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
  trustProxy: true, // ✅ CRITICAL: Trust proxy for Railway/Heroku/Vercel
  handler: (req, res) => {
    console.log(`⚠️ Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      message: 'Too many requests, please try again later.',
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
    });
  }
});

/**
 * Strict rate limiter for authentication routes
 * Prevents brute force attacks on login/register
 */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 attempts per 15 minutes
  message: 'Too many authentication attempts, please try again later.',
  skipSuccessfulRequests: true, // Don't count successful logins
  trustProxy: true, // ✅ CRITICAL
  handler: (req, res) => {
    console.log(`🚨 Auth rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      message: 'Too many authentication attempts. Please try again in 15 minutes.',
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
    });
  }
});

/**
 * Rate limiter for file uploads
 * Prevents storage abuse
 */
export const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // Limit each IP to 20 uploads per hour
  message: 'Too many file uploads, please try again later.',
  trustProxy: true, // ✅ CRITICAL
  handler: (req, res) => {
    console.log(`⚠️ Upload rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      message: 'Too many file uploads. Please try again in an hour.',
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
    });
  }
});

/**
 * Rate limiter for order creation
 * Prevents spam orders
 */
export const orderLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // Limit each IP to 10 orders per minute
  message: 'Too many orders created, please slow down.',
  skipSuccessfulRequests: false,
  trustProxy: true, // ✅ CRITICAL
  handler: (req, res) => {
    console.log(`⚠️ Order rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      message: 'Too many orders. Please wait a moment and try again.',
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
    });
  }
});

/**
 * Rate limiter for password reset requests
 * Prevents enumeration attacks
 */
export const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Only 3 password reset requests per hour
  message: 'Too many password reset attempts.',
  trustProxy: true, // ✅ CRITICAL
  handler: (req, res) => {
    console.log(`🚨 Password reset limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      message: 'Too many password reset attempts. Please try again later.',
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
    });
  }
});