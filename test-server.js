// Simple test server to serve static files
const express = require('express');
const path = require('path');
const app = express();
const PORT = 3002;

// Serve static files from Frontend/dist
app.use(express.static(path.join(__dirname, 'Frontend/dist')));

// For any other routes, serve the index.html
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'Frontend/dist/index.html'));
});

app.listen(PORT, () => {
  console.log(`Test server running at http://localhost:${PORT}`);
});