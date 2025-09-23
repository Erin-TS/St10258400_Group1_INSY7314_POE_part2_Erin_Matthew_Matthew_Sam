//this is the ForgotPassword component for handling password reset process

import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import './FormStyles.css';

const ForgotPassword = () => {
  const [step, setStep] = useState(1); // 1: email, 2: reset code, 3: new password
  const [formData, setFormData] = useState({
    email: '',
    resetCode: '',
    newPassword: '',
    confirmPassword: ''
  });
  
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleEmailSubmit = (e) => {
    e.preventDefault();
    setLoading(true);
    
    // implement email verification logic here
    console.log('Forgot Password - Email:', formData.email);
    
    setTimeout(() => {
      alert('Reset code sent to your email!');
      setStep(2);
      setLoading(false);
    }, 1500);
  };

  const handleCodeSubmit = (e) => {
    e.preventDefault();
    setLoading(true);
    
    // verification logic here 
    console.log('Forgot Password - Reset Code:', formData.resetCode);
    
    setTimeout(() => {
      alert('Code verified! Please enter your new password.');
      setStep(3);
      setLoading(false);
    }, 1500);
  };

  const handlePasswordSubmit = (e) => {
    e.preventDefault();
    
    if (formData.newPassword !== formData.confirmPassword) {
      alert('Passwords do not match');
      return;
    }
    
    setLoading(true);
    
    // implement password reset logic here
    console.log('Forgot Password - New Password:', formData.newPassword);
    
    setTimeout(() => {
      alert('Password reset successful! Please login with your new password.');
      // Clear any existing login data
      localStorage.removeItem('isLoggedIn');
      localStorage.removeItem('userType');
      
      // Navigate to login page
      navigate('/customer-login');
      setLoading(false);
    }, 1500);
  };

  return (
    <div className="form-container">
      <div className="form-card">
        <h2 className="form-title">Forgot Password</h2>
        
        {step === 1 && (
          <form onSubmit={handleEmailSubmit}>
            <p className="form-subtitle">Enter your email address to receive a reset code</p>
            <div className="form-group">
              <label>Email Address</label>
              <input
                type="email"
                name="email"
                placeholder="Enter your email"
                value={formData.email}
                onChange={handleChange}
                className="form-input"
                required
              />
            </div>
            <button type="submit" disabled={loading} className="form-button">
              {loading ? 'Sending...' : 'Send Reset Code'}
            </button>
          </form>
        )}

        {step === 2 && (
          <form onSubmit={handleCodeSubmit}>
            <p className="form-subtitle">Enter the reset code sent to {formData.email}</p>
            <div className="form-group">
              <label>Reset Code</label>
              <input
                type="text"
                name="resetCode"
                placeholder="Enter reset code"
                value={formData.resetCode}
                onChange={handleChange}
                className="form-input"
                maxLength="6"
                required
              />
            </div>
            <button type="submit" disabled={loading} className="form-button">
              {loading ? 'Verifying...' : 'Verify Code'}
            </button>
          </form>
        )}

        {step === 3 && (
          <form onSubmit={handlePasswordSubmit}>
            <p className="form-subtitle">Enter your new password</p>
            <div className="form-group">
              <label>New Password</label>
              <input
                type="password"
                name="newPassword"
                placeholder="Enter new password"
                value={formData.newPassword}
                onChange={handleChange}
                className="form-input"
                required
                minLength="8"
                pattern='(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@$!%*#?&]).{8,}'
                title="Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character"
              />
            </div>
            <div className="form-group">
              <label>Confirm New Password</label>
              <input
                type="password"
                name="confirmPassword"
                placeholder="Confirm new password"
                value={formData.confirmPassword}
                onChange={handleChange}
                className="form-input"
                required
              />
            </div>
            <button type="submit" disabled={loading} className="form-button">
              {loading ? 'Resetting...' : 'Reset Password'}
            </button>
          </form>
        )}

        <div className="form-links">
          <Link to="/customer-login" className="forgot-link">
            Back to Login
          </Link>
        </div>
      </div>
    </div>
  );
};

export default ForgotPassword;