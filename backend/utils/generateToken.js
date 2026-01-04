// utils/generateToken.js - FIXED FOR CROSS-DOMAIN (Vercel + Railway)
import jwt from 'jsonwebtoken';

/**
 * Generate JWT token and set it as HTTP-only cookie
 * @param {object} res - Express response object
 * @param {number} userId - User ID
 * @param {boolean} rememberMe - Whether to extend token expiration (default: false)
 */
const generateToken = (res, userId, rememberMe = false) => {
  // Token expiration time
  // Remember Me: 30 days, Normal: 7 days
  const expiresIn = rememberMe ? '30d' : '7d';
  
  // Generate JWT
  const token = jwt.sign(
    { id: userId }, 
    process.env.JWT_SECRET,
    { expiresIn }
  );

  // Calculate cookie max age in milliseconds
  const maxAge = rememberMe 
    ? 30 * 24 * 60 * 60 * 1000  // 30 days in milliseconds
    : 7 * 24 * 60 * 60 * 1000;   // 7 days in milliseconds

  // ✅ FIXED: Cookie configuration for cross-domain (Vercel frontend + Railway backend)
  const isProduction = process.env.NODE_ENV === 'production';
  
  res.cookie('jwt', token, {
    httpOnly: true,                                    // Prevents XSS attacks (client-side JavaScript cannot access)
    secure: isProduction,                              // HTTPS only in production
    sameSite: isProduction ? 'none' : 'lax',          // ✅ CRITICAL: 'none' for cross-domain in production
    maxAge: maxAge,                                    // Cookie expiration time
    path: '/'                                          // Cookie available for entire domain
  });

  console.log(`✅ Token generated for user ${userId} (Remember Me: ${rememberMe}, Expires: ${rememberMe ? '30 days' : '7 days'})`);
  console.log(`🍪 Cookie settings: secure=${isProduction}, sameSite=${isProduction ? 'none' : 'lax'}`);
  
  return token;
};

export default generateToken;