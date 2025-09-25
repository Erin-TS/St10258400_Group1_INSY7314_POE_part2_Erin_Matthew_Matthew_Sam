import React from 'react';
import { Link } from 'react-router-dom';
import './FormStyles.css';

const Home = () => {
    return (
        <div className="home-container">
            <h1>Welcome to the international payments portal!</h1>
            <div className="portal-sections">
                <div className="Customer-section">
                    <h2>Customer portal</h2>
                    <div className="navigation-links">
                        <Link to="/customer-login" className="nav-link">Login</Link>
                        <Link to="/customer-register" className="nav-link">Register</Link>
                    </div>
                </div>
                <div className="Employee-section">
                    <h2>Employee portal</h2>
                    <div className="navigation-links">
                        <Link to="/employee-login" className="nav-link">Login</Link>
                    </div>
                </div>
            </div>
        </div>
    );
};
export default Home;