//this file is for the react enry point
import React from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import App from './App.js';

// Get the root element from the HTML
const container = document.getElementById('root');
// Create a root.
const root = createRoot(container);


// Initial render
root.render(<React.StrictMode><App /></React.StrictMode>);