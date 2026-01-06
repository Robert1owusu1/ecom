// routes/authRoutes.js
import express from 'express';
import passport from 'passport';
import { generateToken } from '../config/passport.js'; // ✅ Fixed import path

const router = express.Router();

// Helper: Handle OAuth callback success
const handleOAuthSuccess = (req, res) => {
  try {
    const user = req.user;
    
    if (!user) {
      console.error('No user found in OAuth callback');
      return res.redirect(`${process.env.FRONTEND_URL}/login?error=no_user`);
    }
    
    // ✅ Pass res and user.id (MySQL uses 'id', not '_id')
    const token = generateToken(res, user.id);
    
    // Build user data for frontend
    const userData = {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      role: user.role,
      isAdmin: user.role === 'admin',
      isEmailVerified: user.isEmailVerified || 1,
      profilePicture: user.profileImage || user.profile_picture,
      token
    };
    
    const encodedData = encodeURIComponent(JSON.stringify(userData));
    res.redirect(`${process.env.FRONTEND_URL}/oauth/callback?user=${encodedData}&success=true`);
    
  } catch (error) {
    console.error('OAuth success handler error:', error);
    res.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_failed`);
  }
};

// GOOGLE OAUTH ROUTES
router.get('/google', 
  passport.authenticate('google', { 
    scope: ['profile', 'email'],
    session: false 
  })
);

router.get('/google/callback',
  passport.authenticate('google', { 
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=google_failed`,
    session: false 
  }),
  handleOAuthSuccess
);

// FACEBOOK OAUTH ROUTES
router.get('/facebook',
  passport.authenticate('facebook', { 
    scope: ['email', 'public_profile'],
    session: false 
  })
);

router.get('/facebook/callback',
  passport.authenticate('facebook', { 
    failureRedirect: `${process.env.FRONTEND_URL}/login?error=facebook_failed`,
    session: false 
  }),
  handleOAuthSuccess
);

// APPLE OAUTH ROUTES
router.get('/apple', (req, res) => {
  res.status(501).json({ 
    message: 'Apple Sign In not yet implemented',
    info: 'Requires Apple Developer Account and additional configuration'
  });
});

// OAUTH STATUS CHECK
router.get('/status', (req, res) => {
  res.json({
    providers: {
      google: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
      facebook: !!(process.env.FACEBOOK_APP_ID && process.env.FACEBOOK_APP_SECRET),
      apple: false
    }
  });
});

// LOGOUT ROUTE
router.post('/logout', (req, res) => {
  res.cookie('jwt', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    expires: new Date(0)
  });
  
  res.json({ message: 'Logged out successfully' });
});

export default router;