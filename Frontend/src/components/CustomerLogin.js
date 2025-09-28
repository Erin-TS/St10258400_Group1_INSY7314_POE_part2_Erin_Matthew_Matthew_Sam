import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import bcrypt from 'bcryptjs';
import './FormStyles.css';

const CustomerLogin = () => {
    const[formData, setFormData] = useState({
        accountNumber: '',
        username: '',
        password: ''
    });

    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);

        try {
            // Hash the password before processing
            const saltRounds = 12; // You can adjust this (10-12 is recommended)
            const hashedPassword = await bcrypt.hash(formData.password, saltRounds);
            
            // Create a copy of formData with the hashed password
            const formDataWithHashedPassword = {
                ...formData,
                password: hashedPassword
            };

            console.log('Customer login data:', {
                ...formData,
                password: '[HIDDEN]' // Don't log the actual hash
            });

            // In a real application, you would send the hashed password to your backend
            // For demo purposes, we'll store the hashed version
            setTimeout(() => {
                localStorage.setItem('userType', 'customer');
                localStorage.setItem('isLoggedIn', 'false');
                
                // Store the data with hashed password
                localStorage.setItem('customerData', JSON.stringify(formDataWithHashedPassword));
                
                // Also store the original data (without hash) for demo comparison
                // In real app, you'd only store the hashed version
                localStorage.setItem('customerLoginData', JSON.stringify({
                    accountNumber: formData.accountNumber,
                    username: formData.username
                }));

                // Navigate to OTP
                navigate('/otp', { state: { userType: 'customer', from: 'login' } });
                setLoading(false);
            }, 2000);

        } catch (error) {
            console.error('Error hashing password:', error);
            setLoading(false);
            // Handle error (show message to user)
        }
    };

    // Helper function to verify password (for future use)
    const verifyPassword = async (plainPassword, hashedPassword) => {
        try {
            return await bcrypt.compare(plainPassword, hashedPassword);
        } catch (error) {
            console.error('Error verifying password:', error);
            return false;
        }
    };

    return (
        <div className="form-container">
            <div className="form-card">
            <h2 className='form-title'>Customer Login</h2>
            <form onSubmit={handleSubmit}>
                <div className='form-group'>
                <label>Account Number:</label>
                <input
                    type="text"
                    name="accountNumber"
                    value={formData.accountNumber}
                    onChange={handleChange}
                    className='form-input'
                    required
                />
                </div>

                <div className='form-group'>
                <label>Username:</label>
                <input
                    type="text"
                    name="username"
                    value={formData.username}   
                    onChange={handleChange}
                    className='form-input'
                    required
                />
                </div>
                <div className='form-group'>
                <label>Password:</label>
                <input
                    type="password"
                    name="password" 
                    value={formData.password}
                    onChange={handleChange}
                    className='form-input'
                    required    
                />
                </div>
                  <button type="submit" disabled={loading} className="form-button">
            {loading ? 'Logging in...' : 'Continue'}
          </button>
                <p>Don't have an account? <Link to="/customer-register">Register here</Link></p>

                <Link to="/forgot-password" className='forgot-password-link'>Forgot Password?</Link>

            </form>
        </div>
        </div>
    );
};

export default CustomerLogin;