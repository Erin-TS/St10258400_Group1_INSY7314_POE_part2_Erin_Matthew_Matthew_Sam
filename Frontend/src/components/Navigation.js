//this is the navigation bar component
import React from 'react';
import { Link } from 'react-router-dom';
import './Navigation.css';

const Navigation = () => {
    return (
        <nav className="navbar">
            <div className="nav-container">
                <Link to="/" className="nav-logo">
                    International Payments Portal
                </Link>
                <ul className="nav-menu">
                    <li className="nav-item">
                        <Link to="/" className="nav-links">
                            Home
                        </Link>
                    </li>
                    <li className="nav-item">
                        <Link to="/customer-login" className="nav-links">
                            Customer Login
                        </Link>
                    </li>
                    <li className="nav-item">
                        <Link to="/customer-register" className="nav-links">
                            Customer Register
                        </Link>
                    </li>
                    <li className="nav-item">
                        <Link to="/employee-login" className="nav-links">
                            Employee Login
                        </Link>
                    </li>
                </ul>
            </div>
        </nav>
    );
};

export default Navigation;