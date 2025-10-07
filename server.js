import express from 'express'; 
import https from 'https';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import qrcode from 'qrcode';
import speakeasy from 'speakeasy';
import { ObjectId } from 'mongodb';
import db from './db/conn.mjs';

import rateLimit from 'express-rate-limit'; // Import rate limiting middleware
import helmet from 'helmet'; // Import Helmet for security headers
import mongoSanitize from 'express-mongo-sanitize'; // Import MongoDB sanitization
import Joi from 'joi'; // Import Joi for input validation
// Import crypto for generating recovery codes
import crypto from 'crypto';
import { ok } from 'assert';

import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { getCertificatePaths } from './utils/generateCerts.js';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import { body, validationResult } from 'express-validator';
import { safeHTML } from './utils/sanitize.js';

// Load environment variables
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const HTTPS_PORT = process.env.HTTPS_PORT || 5443;
const HTTP_PORT = process.env.HTTP_PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;
const HTTPS_ENABLED = process.env.HTTPS_ENABLED !== 'false';

app.disable('x-powered-by');
app.use((_, res, next) => {                 
  res.set('X-XSS-Protection', '1; mode=block');
  next();
});

// info-leaking hardening headers
// prevents url paths leaking to external sites
app.use((_, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');   // stop MIME-sniff
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
// Joi Validation Schemas
const loginSchema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().min(6).max(128).required(),
    accountNumber: Joi.string().alphanum().min(5).max(20).optional()
});

const registerSchema = Joi.object({
    firstName: Joi.string().pattern(/^[a-zA-Z\s'-]+$/).min(2).max(50).required(),
    lastName: Joi.string().pattern(/^[a-zA-Z\s'-]+$/).min(2).max(50).required(),
    idNumber: Joi.string().min(5).max(20).required(),
    accountNumber: Joi.string().alphanum().min(5).max(20).required(),
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().min(6).max(128).required()
});

const totpVerifySchema = Joi.object({
    token: Joi.string().length(6).pattern(/^[0-9]+$/).required()
});

const hashPasswordSchema = Joi.object({
    password: Joi.string().min(6).max(128).required()
});

// Apply general rate limiting to all requests
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per window
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(apiLimiter);

// Apply specific rate limiting to authentication routes
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per window
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many attempts, please try again later.' }
});

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "frame-ancestors": ["'none'"]
        }
    },
    frameguard: { action: 'deny' },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Middleware with request size limits to prevent payload attacks
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: HTTPS_ENABLED,
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 3600000
    }
}));

// MongoDB NoSQL Injection Protection - sanitizes user input
app.use(mongoSanitize({
    replaceWith: '_', // Replace prohibited characters with underscore
    onSanitize: () => {
        console.warn('Potential NoSQL injection attempt detected and sanitized.');
    }
}));

app.use(express.static(path.join(__dirname, 'Frontend/dist')));

const generateFingerprint = (req) => {
    const userAgent = req.headers['user-agent'] || '';
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    
    const fingerprintData = `${userAgent}|${ip}`;
    return crypto.createHash('sha256').update(fingerprintData).digest('hex');
};

const getClientIP = (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
};

const verifyToken = (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const currentFingerprint = generateFingerprint(req);
        if (decoded.fingerprint !== currentFingerprint) {
            return res.status(401).json({ error: 'Session fingerprint mismatch. Please log in again.' });
        }
        
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token.' });
    }
};

const validate = rules => [                                  
  ...rules,
  (req, res, next) => {
    const err = validationResult(req);
    if (!err.isEmpty()) return res.status(422).json({ error: 'Invalid input', details: err.array() });
    next();
  }
];

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

// Login route with auth rate limiting
app.post('/api/login', authLimiter, validate([
    body('username').trim().matches(/^[A-Za-z0-9_]{3,20}$/),
    body('password').notEmpty().isLength({ min: 8, max: 128 }), 
    body('accountNumber').optional({ checkFalsy: true }).matches(/^\d{10}$/)
]), async (req, res) => {
// Login route with auth rate limiting and validation
app.post('/api/login', authLimiter, async (req, res) => {
    try {
        // Validate input
        const { error, value } = loginSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        const { username, password, accountNumber } = value;

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
            const fingerprint = generateFingerprint(req);
            const clientIP = getClientIP(req);
            const userAgent = req.headers['user-agent'] || 'unknown';
            
            const token = jwt.sign(
                { 
                    id: userData.id, 
                    username: userData.username, 
                    accountNumber: userData.accountNumber,
                    fingerprint: fingerprint,
                    ip: clientIP,
                    ua: userAgent,
                    role: userData.role,
                    iat: Math.floor(Date.now() / 1000)
                },
                JWT_SECRET,
                { expiresIn: '1h' }
            );

            res.cookie('authToken', token, {
                httpOnly: true,
                secure: HTTPS_ENABLED,
                sameSite: 'strict',
                maxAge: 3600000
            });

            res.json({
                message: 'Login successful',
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
    res.clearCookie('authToken', {
        httpOnly: true,
        secure: HTTPS_ENABLED,
        sameSite: 'strict'
    });
    req.session.destroy();
    res.json({ message: 'Logged out successfully.' });
});

// Registration route with auth rate limiting and validation
// prevents script injection and prevents execution of HTML tags
app.post('/api/register', authLimiter, validate([
    body('firstName').trim().escape().isLength({ min: 1, max: 50 }),
    body('lastName').trim().escape().isLength({ min: 1, max: 50 }),
    body('idNumber').trim().matches(/^\d{13}$/),
    body('username').trim().escape().matches(/^[A-Za-z0-9_]{3,20}$/),
    body('password').isStrongPassword(),
    body('accountNumber').trim().matches(/^\d{10}$/) 
  ]), async (req, res) => {
    try {
        // Validate input
        const { error, value } = registerSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        const { firstName, lastName, idNumber, accountNumber, username, password } = value;
        
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
            totpSecret: totpSecret.base32, // Store base32 encoded secret
            totpEnabled: false, // Initially disabled until after first sucessful login
            role: 'customer',
            recoveryCodes: [], // No recovery codes initially
            recoveryCodesGeneratedAt: null
        });

        const qrCodeUrl = await qrcode.toDataURL(totpSecret.otpauth_url);

        res.json({
            message: 'Registration successful',
            userId: result.insertedId,
            qrCode: qrCodeUrl,
            secret: totpSecret.base32, // Send base32 secret for backup
            
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//payment endpoint to store payment details in the database
app.post('/api/payments', verifyToken, validate([
    body('amount').isFloat({ min: 0.01 }),
    body('currency').isIn(['USD', 'EUR', 'GBP', 'AUD', 'CAD', 'NZD', 'ZAR', 'RUB']),
    body('payeeFullName').trim().escape().notEmpty(),
    body('payeeAccountNumber').trim().notEmpty(),
    body('bankName').trim().escape().notEmpty(),
    body('swiftCode').trim().matches(/^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/)
]), async (req, res) => {
    try {
         const payment = {
            userId: req.user.id,
            username: req.user.username,
            ...req.body,
            status: 'pending',
            createdAt: new Date(),
            reference: `PAY${Date.now()}`
        };
  const result = await db.collection('payments').insertOne(payment);
        res.json({ success: true, paymentId: result.insertedId });
    } catch (error) {
        res.status(500).json({ error: 'Payment submission failed' });
    }
});

//get payments endpoint to retrieve payment history
app.get('/api/payments', verifyToken, async (req, res) => {
    try {
        const payments = await db.collection('payments').find({}).toArray();
        res.json({ payments });
    } catch (error) {
        res.status(500).json({ error: 'Failed to retrieve payments' });
    }
});

//approving payments endpoint for employees
app.post('/api/payments/:id/approve', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'employee') {
            return res.status(403).json({ error: 'Access denied' });
        }

        await db.collection('payments').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { status: 'approved', approvedAt: new Date(), approvedBy: req.user.username } }
        );
        res.json({ success: true, message: 'Payment approved' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to approve payment' });
    }   
});

//rejecting payments endpoint for employees
app.post('/api/payments/:id/reject', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'employee') {
            return res.status(403).json({ error: 'Access denied' });
        }
        await db.collection('payments').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { status: 'rejected', rejectedAt: new Date(), rejectedBy: req.user.username } }
        );
        res.json({ success: true, message: 'Payment rejected' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to reject payment' });
    }
});


// Generate a TOTP for hardcoded employee user with auth rate limiting
app.post('/api/register-employee', authLimiter, async (req, res) => {
    try {
        const existingEmployee = await db.collection('users').findOne({ username: 'employee' });

        if (existingEmployee) {
            return res.status(400).json({ error: 'Employee user already exists' });
        }

        const hashedPassword = await bcrypt.hash('password123', 10);

        const totpSecret = speakeasy.generateSecret({ 
            name: 'International payments portal (employee)',
            issuer: 'International payments portal'
        });

        await db.collection('users').insertOne({
            firstName: 'Bob',
            lastName: 'Employee',
            idNumber: 'EMP001',
            accountNumber: null,
            username: 'employee',
            password: hashedPassword,
            totpSecret: totpSecret.base32,
            totpEnabled: true,
            role: 'employee'
        });

        const qrCodeUrl = await qrcode.toDataURL(totpSecret.otpauth_url);

        res.json({
            message: 'Employee user created successfully',
            qrCode: qrCodeUrl,
            totpSecret: totpSecret.base32
        });
    } catch (error) {
        console.error('Employee registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Verify TOTP with validation
app.post('/api/verify-totp', authLimiter, verifyToken, async (req, res) => {
    try {
        // Validate input
        const { error, value } = totpVerifySchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        const { token: totpToken } = value;
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

            // check if  user needs recovery codes
            // User needs recovery codes if they don't have any saved
            const needsRecoveryCodes = !user.recoveryCodes || user.recoveryCodes.length === 0;

            res.json({ 
                message: 'TOTP verification successful',
                success: true,
                needsRecoveryCodes: needsRecoveryCodes
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

// Hash password route with validation
app.post('/api/hash-password', async (req, res) => {
    try {
        // Validate input
        const { error, value } = hashPasswordSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        const { password } = value;
        
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

// Verify recovery code route
app.post('/api/verify-recovery-code', validate([
    body('username').trim().escape().notEmpty().isLength({ min: 3, max: 20 }),
    body('recoveryCode').trim().escape().notEmpty().matches(/^[A-F0-9]{8}$/)
]), async (req, res) => {
    try {
        const { username, recoveryCode } = req.body;
        console.log('>>> username:', username, 'recoveryCode:', recoveryCode);
        if (!username || !recoveryCode)           
        return res.status(400).json({ success: false, message: 'Username and code required' });

        const user = await db.collection('users').findOne({ username });
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        if (!user.recoveryCodes?.length)
        return res.status(400).json({ success: false, message: 'No recovery codes' });

        let valid = false;
        const remaining = [];

    
        for (const hash of user.recoveryCodes) {
        const ok = await bcrypt.compare(recoveryCode.trim().toUpperCase(), hash);
       
        if (!valid && ok) valid = true;
        else remaining.push(hash);
        }

        if (!valid) return res.status(400).json({ success: false, message: 'Invalid code' });

        // delete used code
        const up = await db.collection('users').updateOne(        
            { _id: new ObjectId(user._id) },                     
            { $set: { recoveryCodes: remaining } }
        );
        console.log('>>> update matched:', up.matchedCount, 'modified:', up.modifiedCount); 

        const resetToken = jwt.sign(
            { userId: user._id.toString(), purpose: 'password-reset' },
            process.env.JWT_SECRET,
            { expiresIn: '10m' }
        );

        res.json({ success: true, resetToken, remainingCodes: remaining.length });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Reset password route
app.post('/api/reset-password', validate([
    body('resetToken').isJWT(),
  body('newPassword').isStrongPassword()
]),
    async (req, res) => {
    try {
        const { resetToken, newPassword } = req.body;
        if (!resetToken || !newPassword)
        return res.status(400).json({ success: false, message: 'Token and password required' });

        let decoded;
        try { decoded = jwt.verify(resetToken, process.env.JWT_SECRET); }
        catch { return res.status(400).json({ success: false, message: 'Invalid or expired token' }); }

        if (decoded.purpose !== 'password-reset')
        return res.status(400).json({ success: false, message: 'Bad token' });

        const hash = await bcrypt.hash(newPassword, 10);
        await db.collection('users').updateOne(
        { _id: new ObjectId(decoded.userId) },
        { $set: { password: hash } }
        );

        res.json({ success: true, message: 'Password reset – please log in again' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// generate recovery codes after MFA setup
app.post('/api/generate-recovery-codes', async (req, res) => {
    try {
        const { userId } = req.body;
        console.log('Recovery codes request - userId:', userId);
        
        if (!userId) {
            console.log('Error: No userId provided');
            return res.status(400).json({ success: false, message: 'User ID required' });
        }

        const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });
        console.log('User found:', user ? 'Yes' : 'No');
        
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        if (user.recoveryCodes?.length)   // already generated
        return res.status(400).json({ success: false, message: 'Codes already exist', alreadyGenerated: true });

        const plainCodes = [];
        const hashedCodes = [];

        for (let i = 0; i < 10; i++) {
        const code = crypto.randomBytes(4).toString('hex').toUpperCase(); // 8-char
        plainCodes.push(code);
        hashedCodes.push(await bcrypt.hash(code, 10));
        }

        await db.collection('users').updateOne(
        { _id: new ObjectId(userId) },
        { $set: { recoveryCodes: hashedCodes, recoveryCodesGeneratedAt: new Date() } }
        );

        res.json({ success: true, codes: plainCodes });   // ONLY time user sees them
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Serve frontend for all other routes
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'Frontend/dist/index.html'));
});

if (HTTPS_ENABLED) {
    const credentials = getCertificatePaths();
    
    const httpsServer = https.createServer(credentials, app);
    
    httpsServer.timeout = 30000;
    httpsServer.keepAliveTimeout = 5000;
    httpsServer.headersTimeout = 6000;
    
    httpsServer.listen(HTTPS_PORT, () => {
        console.log(`🔒 HTTPS Server is running on port ${HTTPS_PORT}`);
        console.log(`   Frontend: https://localhost:${HTTPS_PORT}`);
        console.log(`   API: https://localhost:${HTTPS_PORT}/api`);
    });
    
    const httpApp = express();
    httpApp.use((req, res) => {
        res.redirect(301, `https://${req.headers.host.replace(/:\d+$/, `:${HTTPS_PORT}`)}${req.url}`);
    });
    
    const httpServer = http.createServer(httpApp);
    httpServer.listen(HTTP_PORT, () => {
        console.log(`🔓 HTTP Server redirecting to HTTPS on port ${HTTP_PORT}`);
    });
} else {
    const server = app.listen(HTTP_PORT, () => {
        console.log(`⚠️  HTTP Server is running on port ${HTTP_PORT} (HTTPS disabled)`);
        console.log(`   Frontend: http://localhost:${HTTP_PORT}`);
        console.log(`   API: http://localhost:${HTTP_PORT}/api`);
    });
    
    server.timeout = 30000;
    server.keepAliveTimeout = 5000;
    server.headersTimeout = 6000;
}
