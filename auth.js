import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();
const SECRET = process.env.JWT_SECRET || 'secretkey';

/* Register new user */
export const register = async (db, username, password, role = 'user') => {
    const hashed = await bcrypt.hash(password, 10);
    await db.run(
        'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
        [username, hashed, role],
    );
    return { message: 'User registered successfully' };
};

/* Login with password and choose token type */
export const login = async (db, username, password, useJWT = false) => {
    const user = await db.get('SELECT * FROM users WHERE username = ?', [
        username,
    ]);
    if (!user) throw new Error('User not found');
    
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) throw new Error('Invalid password');
    
    if (useJWT) {
        const token = jwt.sign({ id: user.id, role: user.role }, SECRET, {
            expiresIn: '2h',
        });
        return { type: 'JWT', token };
    } else {
        const token = crypto.randomBytes(32).toString('hex');
        await db.run('INSERT INTO access_tokens (user_id, token) VALUES (?, ?)', [
            user.id,
            token,
        ]);
        return { type: 'simple', token };
    }
};

/* Middleware: verify JWT (for Postman/API header) */
export const verifyJWT = (req, res, next) => {
    const header = req.headers['authorization'];
    const token = header && header.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });
    
    jwt.verify(token, SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

/* Middleware: verify simple token (for Postman/API header) */
export const verifySimpleToken = (db) => {
    return async (req, res, next) => {
        const header = req.headers['authorization'];
        const token = header && header.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'Missing token' });
        
        const row = await db.get(
            'SELECT users.id, users.username, users.role FROM access_tokens JOIN users ON users.id = access_tokens.user_id WHERE access_tokens.token = ?',
            [token],
        );
        
        if (!row) return res.status(403).json({ error: 'Invalid token' });
        
        req.user = row;
        next();
    };
};

/* Role-based access */
export const requireRole = (role) => {
    return (req, res, next) => {
        if (req.user.role !== role)
            return res.status(403).json({ error: 'Access denied' });
        next();
    };
};

// ====================================================================
// NEW FUNCTION FOR WEB APPLICATION (COOKIES)
// This function manually parses the raw cookie header without using 'cookie-parser'
// ====================================================================

/* Middleware: verify simple token from cookie (for web pages) */
export const verifySimpleTokenFromCookie = (db) => {
    return async (req, res, next) => {
        const rawCookie = req.headers['cookie']; 
        let token;

        if (rawCookie) {
            const parts = rawCookie.split(';').map(s => s.trim());
            const tokenPart = parts.find(p => p.startsWith('access_token='));
            
            if (tokenPart) {
                token = tokenPart.substring('access_token='.length);
            }
        }
        
        if (!token) {
            return res.redirect('/login'); 
        }

        const row = await db.get(
            'SELECT users.id, users.username, users.role FROM access_tokens JOIN users ON users.id = access_tokens.user_id WHERE access_tokens.token = ?',
            [token]
        );

        if (!row) {
    
            res.setHeader('Set-Cookie', 'access_token=; HttpOnly; Path=/; Max-Age=0');
            return res.redirect('/login');
        }

        req.user = row;
        next();
    };
};