import express from 'express';
// import cookieParser from 'cookie-parser'; // REMOVED
import { initDB } from './db.js';
import {
  register,
  login,
  verifyJWT,
  verifySimpleToken,
  verifySimpleTokenFromCookie, 
  requireRole,
} from './auth.js';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true })); 
// app.use(cookieParser()); // REMOVED

let db;

initDB().then((database) => {
  db = database;

  // --- HTML Page Routes ---
  app.get('/register', (req, res) => res.sendFile('register.html', { root: '.' }));
  app.get('/login', (req, res) => res.sendFile('login.html', { root: '.' }));
  
  // PROTECTED WEB PROFILE route
  app.get('/profile', verifySimpleTokenFromCookie(db), (req, res) => {
    res.sendFile('profile.html', { root: '.' });
  });

  // --- Public API Routes ---
  app.post('/api/register', async (req, res) => {
    try {
      const { username, password, role } = req.body;
      await register(db, username, password, role || 'user'); 
      res.redirect('/login');
    } catch (e) {
      res.status(400).send(`Registration failed: ${e.message}`);
    }
  });

  // LOGIN (Sets the cookie manually using res.setHeader)
  app.post('/api/login', async (req, res) => {
    try {
      const { username, password, jwt: useJWT } = req.body;
      const result = await login(db, username, password, useJWT); 
      
      if (useJWT) {
          return res.json(result);
      }
      
      // *** MANUAL HEADER CREATION ***
      const cookieString = `access_token=${result.token}; HttpOnly; Path=/; SameSite=Lax`;
      res.setHeader('Set-Cookie', cookieString); 
      
      return res.redirect('/profile'); 
    } catch (e) {
      res.status(400).send(`Login failed: ${e.message}`);
    }
  });

  // --- Postman API Protected Routes (No change here) ---
  app.get('/profile/jwt', verifyJWT, async (req, res) => { /* ... */ });
  app.get('/profile/simple', verifySimpleToken(db), async (req, res) => { /* ... */ });
  app.get('/admin/users', verifyJWT, requireRole('admin'), async (req, res) => { /* ... */ });

  // --- Task Manager Routes (No change here) ---
  app.post('/tasks', verifyJWT, async (req, res) => { /* ... */ });
  app.get('/tasks', verifyJWT, async (req, res) => { /* ... */ });
  app.delete('/tasks/:id', verifyJWT, async (req, res) => { /* ... */ });
  app.get('/admin/tasks', verifyJWT, requireRole('admin'), async (req, res) => { /* ... */ });

  app.listen(3000, () => console.log('Server running on http://localhost:3000'));
});