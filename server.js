const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const ExpressBrute = require('express-brute');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Brute force protection
const store = new ExpressBrute.MemoryStore(); // stores state locally, don't use this in production
const bruteforce = new ExpressBrute(store, {
    freeRetries: 5, // Allow 5 free attempts
    minWait: 5*60*1000, // 5 minutes
    maxWait: 60*60*1000, // 1 hour
    failCallback: function (req, res, next, nextValidRequestDate) {
        res.status(429).json({ 
            error: 'Too many failed attempts, please try again later.',
            nextValidRequestDate: nextValidRequestDate
        });
    }
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
    secret: 'your-session-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to true in production with HTTPS
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// JWT verification middleware
const verifyToken = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(400).json({ error: 'Invalid token.' });
    }
};

// Serve static files from the React app build directory
app.use(express.static(path.join(__dirname, 'Frontend/dist')));

// API routes

// Test route
app.get('/api/test', (req, res) => {
    res.json({ message: 'Backend server is working!' });
});

// Login route with brute force protection
app.post('/api/login', bruteforce.prevent, async (req, res) => {
    try {
        const { username, password, accountNumber } = req.body;
        
        // TODO: Replace with actual database lookup
        // This is just for demonstration
        const user = {
            id: 1,
            username: 'testuser',
            accountNumber: '12345',
            // This should be a hashed password from your database
            passwordHash: await bcrypt.hash('password123', 10)
        };
        
        // Validate credentials
        if (username === user.username && 
            accountNumber === user.accountNumber &&
            await bcrypt.compare(password, user.passwordHash)) {
            
            // Create JWT token
            const token = jwt.sign(
                { userId: user.id, username: user.username },
                JWT_SECRET,
                { expiresIn: '24h' }
            );
            
            res.json({
                message: 'Login successful',
                token: token,
                user: {
                    id: user.id,
                    username: user.username,
                    accountNumber: user.accountNumber
                }
            });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Protected route example
app.get('/api/protected', verifyToken, (req, res) => {
    res.json({ 
        message: 'This is a protected route',
        user: req.user
    });
});

// Password hashing utility route (for testing)
app.post('/api/hash-password', async (req, res) => {
    try {
        const { password } = req.body;
        const saltRounds = 10;
        const hash = await bcrypt.hash(password, saltRounds);
        res.json({ hash });
    } catch (error) {
        res.status(500).json({ error: 'Error hashing password' });
    }
});

// Catch all handler: send back React's index.html file for any non-API routes
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'Frontend/dist/index.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Frontend: http://localhost:${PORT}`);
    console.log(`API: http://localhost:${PORT}/api`);
});