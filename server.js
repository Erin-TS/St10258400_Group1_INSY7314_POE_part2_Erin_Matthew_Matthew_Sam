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
// Import crypto for generating recovery codes
import crypto from 'crypto';

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
            }else{
                return res.status(401).json({ error: 'Employee not configured' });
            }

      
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
            name: `International Payments Portal (${username})`,
            issuer: 'International payments portal'
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
            role: 'customer',
            recoveryCodes: [], // No recovery codes initially
            recoveryCodesGeneratedAt: null
        });

        // Generate QR code for the TOTP secret
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

//generate a totp for hardcoded employee user
app.post('/api/register-employee', async (req, res) => {
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

// Verify recovery code route
app.post('/api/verify-recovery-code', async (req, res) => {
    try {
        const { username, recoveryCode } = req.body;
        if (!username || !recoveryCode)
        return res.status(400).json({ success: false, message: 'Username and code required' });

        const user = await db.collection('users').findOne({ username });
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        if (!user.recoveryCodes?.length)
        return res.status(400).json({ success: false, message: 'No recovery codes' });

        let valid = false;
        const remaining = [];

        for (const hash of user.recoveryCodes) {
        if (!valid && (await bcrypt.compare(recoveryCode.trim().toUpperCase(), hash))) valid = true;
        else remaining.push(hash);
        }

        if (!valid) return res.status(400).json({ success: false, message: 'Invalid code' });

        // delete used code
        await db.collection('users').updateOne(
        { _id: user._id },
        { $set: { recoveryCodes: remaining } }
        );

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
app.post('/api/reset-password', async (req, res) => {
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
        if (!userId) return res.status(400).json({ success: false, message: 'User ID required' });

        const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });
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

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Frontend: http://localhost:${PORT}`);
    console.log(`API: http://localhost:${PORT}/api`);
});

