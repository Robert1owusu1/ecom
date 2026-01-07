// config/passport.js
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import pool from './db.js';
import jwt from 'jsonwebtoken';

// Helper: Find or create user from OAuth profile
const findOrCreateOAuthUser = async (provider, profile) => {
  let connection;
  try {
    connection = await pool.getConnection();
    
    const providerId = `${provider}Id`;
    const email = profile.emails?.[0]?.value?.toLowerCase();
    
    // 1. Check if user exists by provider ID
    const [existingByProvider] = await connection.execute(
      `SELECT * FROM users WHERE ${providerId} = ?`,
      [profile.id]
    );
    
    if (existingByProvider.length > 0) {
      console.log(`✅ Found existing user by ${provider}Id`);
      return existingByProvider[0];
    }
    
    // 2. Check if user exists by email (link accounts)
    if (email) {
      const [existingByEmail] = await connection.execute(
        'SELECT * FROM users WHERE email = ?',
        [email]
      );
      
      if (existingByEmail.length > 0) {
        await connection.execute(
          `UPDATE users SET ${providerId} = ?, isEmailVerified = 1 WHERE id = ?`,
          [profile.id, existingByEmail[0].id]
        );
        console.log(`✅ Linked ${provider} to existing account`);
        return { ...existingByEmail[0], [providerId]: profile.id, isEmailVerified: 1 };
      }
    }
    
    // 3. Create new user
    const firstName = profile.name?.givenName || profile.displayName?.split(' ')[0] || 'User';
    const lastName = profile.name?.familyName || profile.displayName?.split(' ').slice(1).join(' ') || '';
    const profilePicture = profile.photos?.[0]?.value || null;
    
    const [result] = await connection.execute(
      `INSERT INTO users (firstName, lastName, email, ${providerId}, password, isEmailVerified, profileImage, role, isActive)
       VALUES (?, ?, ?, ?, ?, 1, ?, 'customer', 1)`,
      [firstName, lastName, email || `${provider}_${profile.id}@oauth.local`, profile.id, 'OAUTH_NO_PASSWORD', profilePicture]
    );
    
    console.log(`✅ Created new user via ${provider} OAuth`);
    
    const [newUser] = await connection.execute('SELECT * FROM users WHERE id = ?', [result.insertId]);
    return newUser[0];
    
  } catch (error) {
    console.error(`❌ OAuth ${provider} error:`, error);
    throw error;
  } finally {
    if (connection) connection.release();
  }
};

// Generate JWT token and set cookie
export const generateToken = (res, userId) => {
  const token = jwt.sign(
    { id: userId },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );

  // Set HTTP-only cookie
  res.cookie('jwt', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 30 * 24 * 60 * 60 * 1000,
    path: '/'
  });

  return token;
};

// Configure Passport strategies
export const configurePassport = () => {
  
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    const baseURL = process.env.RAILWAY_PUBLIC_DOMAIN 
      ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
      : process.env.OAUTH_CALLBACK_URL || 'http://localhost:5000';
    
    // ✅ FIXED: Added /api prefix to callback URL
    const googleCallbackURL = `${baseURL}/api/auth/google/callback`;
    
    console.log('🔐 Google OAuth Callback URL:', googleCallbackURL);

    passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: googleCallbackURL,
      scope: ['profile', 'email']
    }, async (accessToken, refreshToken, profile, done) => {
      try {
        console.log('✅ Google OAuth callback received for:', profile.emails[0].value);
        const user = await findOrCreateOAuthUser('google', profile);
        return done(null, user);
      } catch (error) {
        console.error('❌ Google OAuth error:', error);
        return done(error, null);
      }
    }));
    console.log('✅ Google OAuth configured');
  }

  if (process.env.FACEBOOK_APP_ID && process.env.FACEBOOK_APP_SECRET) {
    const baseURL = process.env.RAILWAY_PUBLIC_DOMAIN 
      ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
      : process.env.OAUTH_CALLBACK_URL || 'http://localhost:5000';
    
    // ✅ FIXED: Callback URL already had /api, keeping it consistent
    const facebookCallbackURL = `${baseURL}/api/auth/facebook/callback`;
    
    console.log('🔐 Facebook OAuth Callback URL:', facebookCallbackURL);

    passport.use(new FacebookStrategy({
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: facebookCallbackURL,
      profileFields: ['id', 'emails', 'name', 'displayName', 'photos']
    }, async (accessToken, refreshToken, profile, done) => {
      try {
        console.log('✅ Facebook OAuth callback received');
        const user = await findOrCreateOAuthUser('facebook', profile);
        return done(null, user);
      } catch (error) {
        console.error('❌ Facebook OAuth error:', error);
        return done(error, null);
      }
    }));
    console.log('✅ Facebook OAuth configured');
  }

  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [id]);
      done(null, rows[0] || null);
    } catch (error) {
      done(error, null);
    }
  });
};

export default passport;