// midleware/authMiddleware.js
import jwt from 'jsonwebtoken';
import asyncHandler from './asyncHandller.js';
import User from '../models/usersModel.js';

/**
 * Protect routes - Verify JWT token from header or cookie
 */
const protect = asyncHandler(async (req, res, next) => {
  let token;

  // 1. Try Authorization header first (for API clients)
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  // 2. Fallback to cookie (for browser/local dev)
  else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  // No token found
  if (!token) {
    res.status(401);
    throw new Error('Not authorized, no token');
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Get user from database
    const user = await User.findById(decoded.id);

    // Check if user exists
    if (!user) {
      res.status(401);
      throw new Error('User not found');
    }

    // Check if user is active
    if (!user.isActive) {
      res.status(403);
      throw new Error('Account is deactivated');
    }

    // Attach user profile to request
    req.user = user.getProfile();
    
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    res.status(401);
    
    // More specific error messages
    if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid token');
    } else if (error.name === 'TokenExpiredError') {
      throw new Error('Token expired');
    }
    
    throw new Error('Not authorized, token failed');
  }
});

/**
 * Admin middleware - Check if user is admin
 */
const admin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403);
    throw new Error('Not authorized as admin');
  }
};

export { protect, admin };