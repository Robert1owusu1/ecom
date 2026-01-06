// routes/authRoutes.js
import express from 'express';
import passport from 'passport';
import { generateToken } from '../config/passport.js';

const router = express.Router();

const handleOAuthSuccess = (req, res) => {
  try {
    const user = req.user;
    
    if (!user) {
      console.error('No user found in OAuth callback');
      return res.redirect(`${process.env.FRONTEND_URL}/login?error=no_user`);
    }
    
    const token = generateToken(res, user.id);
    
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

router.post('/logout', (req, res) => {
  res.cookie('jwt', '', {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    expires: new Date(0)
  });
  
  res.json({ message: 'Logged out successfully' });
});

export default router;