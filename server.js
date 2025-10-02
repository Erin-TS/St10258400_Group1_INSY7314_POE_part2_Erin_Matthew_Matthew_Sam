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
import db from './db/conn.mjs';

// Load environment variables
dotenv.config();

// ES module equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'Frontend/dist')));

// JWT Verification Middleware
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Bearer <token>
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

// Test route
app.get('/api/test', (req, res) => {
    res.json({ message: 'Backend server is working!' });
});

// Test MongoDB connection route
app.get('/api/db-test', async (req, res) => {
    try {
        // Test if we can access the database
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
app.post('/api/login', async (req, res) => {
    try {
        const { username, password, accountNumber } = req.body;

        let isValid = false;
        let userData = null;

        if (username === 'employee' && password === 'password123' && !accountNumber) {
            // Hardcoded employee login for demonstration purposes
            isValid = true;
            userData = { id: 2, username: 'employee', accountNumber: null };
        } else {
            // Fetch user from the database
            const user = await db.collection('users').findOne({ username });
            if (user) {
                // Bcrypt is used to compare the entered password with the stored hash
                const isPasswordValid = await bcrypt.compare(password, user.password);
                if (isPasswordValid) {
                    if (accountNumber && user.accountNumber !== accountNumber) {
                        return res.status(401).json({ error: 'Invalid credentials' });
                    }
                    isValid = true;
                    userData = { id: user._id, username: user.username, accountNumber: user.accountNumber };
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
                user: userData
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

//logout route
app.post('/api/logout', (req, res) => {
    // For JWT, logout is handled client-side by removing the token
    res.json({ message: 'Logged out successfully. Please remove the token from client storage.' });
});

// Registration route
//generate a totp secret for a user when registering
app.post('/api/register', async (req, res) => {
    try {
        const { firstName, lastName, idNumber, accountNumber, username, password } = req.body;
        // Check if user already exists
        const existingUser = await db.collection('users').findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash and salt the password using bcrypt
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Generate TOTP secret
        const totpSecret = speakeasy.generateSecret({ 
            name: 'International payments portal (${username})',
            issuer: 'Inrernational payments portal'
        });

        // Insert new user with hashed password and TOTP secret
        const result = await db.collection('users').insertOne({
            firstName,
            lastName,
            idNumber,
            accountNumber,
            username,
            password: hashedPassword,
            totpSecret: totpSecret.base32, // Store base32 encoded secret
            totpEnabled: false, // Initially disabled until after first sucessful login
            role: 'customer'
        });

        // Generate QR code for the TOTP secret
        const qrCodeUrl = await qrcode.toDataURL(totpSecret.otpauth_url);

        res.json({
            message: 'Registration successful',
            userId: result.insertedId,
            qrCode: qrCodeUrl,
            totpSecret: totpSecret.base32 // Send base32 secret for backup
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//verify totp route
//verify a totp token during login
app.post('/api/verify-totp', verifyToken, async (req, res) => {
    try {
        const { token: totpToken } = req.body;
        const userId = req.user.id;

        // Fetch user from the database
        const user = await db.collection('users').findOne({ 
            $or: [
                {_id: new ObjectId(userId) },
                {username: req.user.username } 
            ]
        });
        if(!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Verify the TOTP token
        const isTokenValid = speakeasy.totp.verify({
            secret: user.totpSecret,
            encoding: 'base32',
            token: totpToken,
            window: 2 // Allow a window of 2 time steps (default is 30 seconds each)
        });

        if (isTokenValid) {
            // If TOTP is valid and not yet enabled, enable it now
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

//setup totp route
//get qr code for existing user to set up 2fa incase they lose their device and need to set it up again
app.get('/api/setup-totp', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;

        // Fetch user from the database
        const user = await db.collection('users').findOne({
            $or: [
                { _id: new ObjectId(userId) },
                { username: req.user.username }
            ]
        });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Generate QR code for the TOTP secret
        const otpAuthUrl = speakeasy.otpauthURL({
            secret: user.totpSecret,
            label: user.username,
            issuer: `International payments portal (${user.username})`,
            encoding: 'base32'
        });

        const qrCodeUrl = await qrcode.toDataURL(otpAuthUrl);

        res.json({
            qrCode: qrCodeUrl,
            totpSecret: user.totpSecret // Send base32 secret for backup
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
        
        // Hash the password using bcrypt
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

