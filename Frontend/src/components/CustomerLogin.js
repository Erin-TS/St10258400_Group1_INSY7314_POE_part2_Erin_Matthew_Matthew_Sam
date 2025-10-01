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

        //handle login logic here
        console.log('Customer login data:', formData);

        setTimeout(() => {
            localStorage.setItem('userType', 'customer'); // Store user type in localStorage
            localStorage.setItem('isLoggedIn', 'false'); // Set true after OTP verification
            localStorage.setItem('customerData', JSON.stringify(formData)); // Store customer data

        //after  login navigate to opt
        navigate('/otp', { state: { userType: 'customer',from : 'login' } });
        setLoading(false);
        }, 2000); // Simulate a 2-second loading time
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