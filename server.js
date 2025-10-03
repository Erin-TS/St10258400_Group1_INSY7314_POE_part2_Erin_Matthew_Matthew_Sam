import express from 'express'; 
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
// 2Fa libraries
import qrcode from 'qrcode';
import speakeasy from 'speakeasy';
// Import the MongoDB connection
import { ObjectId } from 'mongodb';
import db from './db/conn.mjs';

import rateLimit from 'express-rate-limit'; // Import rate limiting middleware
import helmet from 'helmet'; // Import Helmet for security headers

// Load environment variables
dotenv.config();

// ES module equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// Apply general rate limiting to all requests
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(apiLimiter);

// Apply specific rate limiting to authentication routes
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per window
    message: { error: 'Too many attempts, please try again later.' }
});

// Apply Helmet for security headers
app.use(helmet());

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'Frontend/dist')));

// JWT Verification Middleware
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token.' });
    }
};

// API routes

app.get('/api/test', (req, res) => {
    res.json({ message: 'Backend server is working!' });
});

app.get('/api/db-test', async (req, res) => {
    try {
        const result = await db.admin().ping();
        res.json({ 
            message: 'MongoDB connection successful!', 
            database: 'INSY7314-Cluster',
            ping: result 
        });
    } catch (error) {
        console.error('Database connection error:', error);
        res.status(500).json({ 
            error: 'Database connection failed', 
            details: error.message 
        });
    }
});

// Login route 
app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { username, password, accountNumber } = req.body;

        let isValid = false;
        let userData = null;

        if (username === 'employee' && password === 'password123' && !accountNumber) {
            const employeeUser = await db.collection('users').findOne({ username: 'employee' });

            if (employeeUser) {
                isValid= true;
                userData = { 
                    id: employeeUser._id,
                    username: employeeUser.username,
                    accountNumber: employeeUser.accountNumber,
                    role: employeeUser.role,
                    totpEnabled: employeeUser.totpEnabled || false 
                };
            } else {
                return res.status(401).json({ error: 'Employee not configured' });
            }
        } else {
            const user = await db.collection('users').findOne({ username });
            if (user) {
                const isPasswordValid = await bcrypt.compare(password, user.password);
                if (isPasswordValid) {
                    if (accountNumber && user.accountNumber !== accountNumber) {
                        return res.status(401).json({ error: 'Invalid credentials' });
                    }
                
                    isValid = true;
                    userData = { 
                        id: user._id, 
                        username: user.username, 
                        accountNumber: user.accountNumber,
                        role: user.role,
                        totpEnabled: user.totpEnabled || false 
                    };
                }
            }
        }

        if (isValid) {
            const token = jwt.sign(
                { id: userData.id, username: userData.username, accountNumber: userData.accountNumber },
                JWT_SECRET,
                { expiresIn: '1h' }
            );

            res.json({
                message: 'Login successful',
                token: token,
                user: userData,
                requiresMFA: true
            });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Protected route 
app.get('/api/protected', verifyToken, (req, res) => {
    res.json({
        message: 'This is a protected route',
        user: req.user
    });
});

// Logout route
app.post('/api/logout', (req, res) => {
    res.json({ message: 'Logged out successfully. Please remove the token from client storage.' });
});

// Registration route
app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { firstName, lastName, idNumber, accountNumber, username, password } = req.body;
        const existingUser = await db.collection('users').findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const totpSecret = speakeasy.generateSecret({ 
            name: `International Payments Portal (${username})`,
            issuer: 'International payments portal'
        });

        const result = await db.collection('users').insertOne({
            firstName,
            lastName,
            idNumber,
            accountNumber,
            username,
            password: hashedPassword,
            totpSecret: totpSecret.base32,
            totpEnabled: false,
            role: 'customer'
        });

        const qrCodeUrl = await qrcode.toDataURL(totpSecret.otpauth_url);

        res.json({
            message: 'Registration successful',
            userId: result.insertedId,
            qrCode: qrCodeUrl,
            secret: totpSecret.base32
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Verify TOTP 
app.post('/api/verify-totp', verifyToken, authLimiter, async (req, res) => {
    try {
        const { token: totpToken } = req.body;
        const userId = req.user.id;

        const user = await db.collection('users').findOne({ 
            $or: [
                {_id: new ObjectId(userId) },
                {username: req.user.username } 
            ]
        });
        if(!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const isTokenValid = speakeasy.totp.verify({
            secret: user.totpSecret,
            encoding: 'base32',
            token: totpToken,
            window: 2 
        });

        if (isTokenValid) {
            if (!user.totpEnabled) {
                await db.collection('users').updateOne(
                    { _id: user._id },
                    { $set: { totpEnabled: true } }
                );
            }

            res.json({ 
                message: 'TOTP verification successful',
                success: true
            });
        } else {
            res.status(401).json({ 
                error: 'Invalid TOTP token',
                success: false
            });
        }
    } catch (error) {
        console.error('TOTP verification error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Setup TOTP 
app.get('/api/setup-totp', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;

        const user = await db.collection('users').findOne({
            $or: [
                { _id: new ObjectId(userId) },
                { username: req.user.username }
            ]
        });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const otpAuthUrl = speakeasy.otpauthURL({
            secret: user.totpSecret,
            label: user.username,
            issuer: `International payments portal (${user.username})`,
            encoding: 'base32'
        });

        const qrCodeUrl = await qrcode.toDataURL(otpAuthUrl);

        res.json({
            qrCode: qrCodeUrl,
            totpSecret: user.totpSecret
        });
    } catch (error) {
        console.error('Setup TOTP error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Hash password route
app.post('/api/hash-password', async (req, res) => {
    try {
        const { password } = req.body;
        
        if (!password) {
            return res.status(400).json({ error: 'Password is required' });
        }
        
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        res.json({ 
            message: 'Password hashed successfully'
        });
    } catch (error) {
        console.error('Hash password error:', error);
        res.status(500).json({ error: 'Error processing request' });
    }
});

// Serve frontend for all other routes
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'Frontend/dist/index.html'));
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Frontend: http://localhost:${PORT}`);
    console.log(`API: http://localhost:${PORT}/api`);
});
