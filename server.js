const express = require('express');
const path = require('path');

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