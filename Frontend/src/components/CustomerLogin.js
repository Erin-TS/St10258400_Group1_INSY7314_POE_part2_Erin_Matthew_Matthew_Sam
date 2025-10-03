import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import './FormStyles.css';

const CustomerLogin = () => {
    const[formData, setFormData] = useState({
        username: '',
        password: '',
        accountNumber: ''
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
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: formData.username,
                    password: formData.password,
                    accountNumber: formData.accountNumber
            })
    });

            const data = await response.json();

            if (response.ok) {
                localStorage.setItem('token', data.token);
                localStorage.setItem('userType', 'customer');
                
                navigate('/otp', { state: { userType: 'customer', from: 'login' } });
            } else {
                alert(data.error || 'Login failed');
            }
        } catch (error) {
            console.error('Login error:', error);
            alert('An error occurred during login');
        } finally {
            setLoading(false);
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