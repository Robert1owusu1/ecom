// middleware/authMiddleware.js
import jwt from 'jsonwebtoken';
import asyncHandler from './asyncHandler.js'; // ✅ Fixed typo
import pool from '../config/db.js'; // ✅ Use MySQL pool

/**
 * Protect routes - Verify JWT token from header or cookie
 */
const protect = asyncHandler(async (req, res, next) => {
  let token;

  // 1. Try Authorization header first
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  // 2. Fallback to cookie
  else if (req.cookies?.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    res.status(401);
    throw new Error('Not authorized, no token');
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // ✅ Get user from MySQL database
    const [rows] = await pool.execute(
      'SELECT id, firstName, lastName, email, role, isActive, isEmailVerified, profileImage FROM users WHERE id = ?',
      [decoded.id]
    );

    const user = rows[0];

    if (!user) {
      res.status(401);
      throw new Error('User not found');
    }

    if (!user.isActive) {
      res.status(403);
      throw new Error('Account is deactivated');
    }

    // Attach user to request
    req.user = user;
    next();

  } catch (error) {
    console.error('Token verification error:', error.message);
    res.status(401);
    
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