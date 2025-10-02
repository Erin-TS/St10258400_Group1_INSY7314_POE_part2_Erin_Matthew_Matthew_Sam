import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
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

app.get('/api/protected', verifyToken, (req, res) => {
    res.json({
        message: 'This is a protected route',
        user: req.user
    });
});

app.post('/api/logout', (req, res) => {
    // For JWT, logout is handled client-side by removing the token
    res.json({ message: 'Logged out successfully. Please remove the token from client storage.' });
});

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

        // Insert new user with hashed password
        const result = await db.collection('users').insertOne({
            firstName,
            lastName,
            idNumber,
            accountNumber,
            username,
            password: hashedPassword, 
            role: 'customer'
        });

        res.json({
            message: 'Registration successful',
            userId: result.insertedId
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

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
            message: 'Password hashed successfully',
            hashedPassword: hashedPassword 
        });
    } catch (error) {
        console.error('Hash password error:', error);
        res.status(500).json({ error: 'Error processing request' });
    }
});

app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'Frontend/dist/index.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Frontend: http://localhost:${PORT}`);
    console.log(`API: http://localhost:${PORT}/api`);
});