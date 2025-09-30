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


// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'Frontend/dist')));

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
        
        
        if (username === 'testuser' && password === 'password123' && accountNumber === '12345') {
            
            
            
            res.json({
                message: 'Login successful',
               
                user: {
                    id: 1,
                    username: username,
                    accountNumber: accountNumber
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


app.get('/api/protected', (req, res) => {
    res.json({ 
        message: 'This is a protected route',
       
    });
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