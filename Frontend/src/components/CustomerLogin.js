//this is the  customer login component so the customer can login
import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import './FormStyles.css';

const CustomerLogin = () => {
    const[formData, setFormData] = useState({
        accountNumber: '',
        username: '',
        password: ''
    });

    const navigate = useNavigate();

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        //handle login logic here
        console.log('Customer login data:', formData);
        //after  login navigate to opt
        navigate('/otp');
    };

    return (
        <div className="form-container">
            <h2>Customer Login</h2>
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
                <button type="submit" className='form-button'>Continue</button>

                <p>Don't have an account? <Link to="/CustomerRegister">Register here</Link></p>

                <Link to="/forgot-password" className='forgot-password-link'>Forgot Password?</Link>

            </form>
        </div>
    );
}
export default CustomerLogin;