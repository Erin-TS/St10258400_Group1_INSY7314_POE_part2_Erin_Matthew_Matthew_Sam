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
            role: 'customer'
        });

        // Generate QR code for the TOTP secret
        const qrCodeUrl = await qrcode.toDataURL(totpSecret.otpauth_url);

        res.json({
            message: 'Registration successful',
            userId: result.insertedId,
            qrCode: qrCodeUrl,
            secret: totpSecret.base32 // Send base32 secret for backup
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

// Verify recovery code route
// Verify recovery code and issue a reset token
app.post("/api/verify-recovery-code", async (req, res) => {
  try {
    const { recoveryCode } = req.body;

    // Find user with matching recovery code
    const user = await db.collection("users").findOne({ recoveryCodes: { $exists: true } });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    let isValid = false;
    let remainingCodes = [];

    for (const hashedCode of user.recoveryCodes) {
      if (await bcrypt.compare(recoveryCode, hashedCode)) {
        isValid = true;
      } else {
        remainingCodes.push(hashedCode);
      }
    }

    if (!isValid) {
      return res.status(400).json({ success: false, message: "Invalid recovery code" });
    }

    // Remove used recovery code
    await db.collection("users").updateOne(
      { _id: user._id },
      { $set: { recoveryCodes: remainingCodes } }
    );

    const resetToken = jwt.sign(
      { userId: user._id.toString(), purpose: "password-reset" },
      process.env.JWT_SECRET,
      { expiresIn: "10m" }
    );

    res.status(200).json({ success: true, resetToken });
  } catch (error) {
    console.error("Verify recovery code error:", error);
    res.status(500).json({ success: false, message: "Error verifying recovery code" });
  }
});

// Reset password route
app.post("/api/reset-password", async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;

    let decoded;
    try {
      decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(400).json({ success: false, message: "Invalid or expired reset token" });
    }

    if (decoded.purpose !== "password-reset") {
      return res.status(400).json({ success: false, message: "Invalid reset token" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.collection("users").updateOne(
      { _id: new ObjectId(decoded.userId) },
      { $set: { password: hashedPassword } }
    );

    res.status(200).json({ success: true, message: "Password reset successful" });
  } catch (error) {
    console.error("Password reset error:", error);
    res.status(500).json({ success: false, message: "Error resetting password" });
  }
});

// generate recovery codes route
app.post('/api/generate-recovery-codes', async (req, res) => {
    try {
        const userId = req.user?.id || req.body.userId;

        if (!userId) {
            return res.status(401).json({ success: false, message: 'Authentication required' });
        }

        // Check if user already has recovery codes
    const user = await db.collection("users").findOne(
      { _id: new ObjectId(userId) },
      { projection: { recoveryCodes: 1 } }
    );

    if (user?.recoveryCodes && user.recoveryCodes.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: "Recovery codes already exist for this account",
        alreadyGenerated: true 
      });
    }
    // Generate 10 recovery codes
    const codes = [];
    const hashedCodes = [];

    for (let i = 0; i < 10; i++) {
      const code = crypto.randomBytes(4).toString("hex").toUpperCase();
      codes.push(code);
      
      const hashedCode = await bcrypt.hash(code, 10);
      hashedCodes.push({
        code: hashedCode,
        used: false,
        createdAt: new Date()
      });
    }

    // Save to database
    await db.collection("users").updateOne(
      { _id: new ObjectId(userId) },
      { 
        $set: { 
          recoveryCodes: hashedCodes,
          recoveryCodesGeneratedAt: new Date()
        } 
      }
    );

    res.status(200).json({ 
      success: true, 
      codes: codes // Send plain codes to user (only time they'll see them)
    });

  } catch (error) {
    console.error("Generate recovery codes error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Error generating recovery codes" 
    });
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

