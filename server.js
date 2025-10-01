
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
// Import the MongoDB connection
import db from './db/conn.mjs';

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

        // For simplicity, allow login without accountNumber for employees
        const isValid = (username === 'testuser' && password === 'password123' && accountNumber === '12345') ||
                        (username === 'employee' && password === 'password123' && !accountNumber);

        if (isValid) {
            const userId = username === 'employee' ? 2 : 1;
            const token = jwt.sign(
                { id: userId, username: username, accountNumber: accountNumber || null },
                JWT_SECRET,
                { expiresIn: '1h' }
            );

            res.json({
                message: 'Login successful',
                token: token,
                user: {
                    id: userId,
                    username: username,
                    accountNumber: accountNumber || null
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

app.post('/api/hash-password', async (req, res) => {
    try {
        const { password } = req.body;
       
        res.json({ message: 'Password hashing disabled for development', password: password });
    } catch (error) {
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
    console.log(`Security features disabled for development - check TODO comments to enable`);
});