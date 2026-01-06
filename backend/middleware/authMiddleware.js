// middleware/authMiddleware.js
import jwt from 'jsonwebtoken';
import asyncHandler from './asyncHandller.js';
import pool from '../config/db.js';

const protect = asyncHandler(async (req, res, next) => {
  let token;

  console.log('🔍 Cookies:', req.cookies);
  console.log('🔍 Auth header:', req.headers.authorization);

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
    console.log('✅ Token from header');
  }
  else if (req.cookies?.jwt) {
    token = req.cookies.jwt;
    console.log('✅ Token from cookie');
  }

  if (!token) {
    console.log('❌ No token found');
    res.status(401);
    throw new Error('Not authorized, no token');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('✅ Token verified for user:', decoded.id);

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

    req.user = user;
    console.log('✅ User authenticated:', user.email);
    next();

  } catch (error) {
    console.error('❌ Token error:', error.message);
    res.status(401);
    
    if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid token');
    } else if (error.name === 'TokenExpiredError') {
      throw new Error('Token expired');
    }
    
    throw new Error('Not authorized, token failed');
  }
});

const admin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403);
    throw new Error('Not authorized as admin');
  }
};

export { protect, admin };