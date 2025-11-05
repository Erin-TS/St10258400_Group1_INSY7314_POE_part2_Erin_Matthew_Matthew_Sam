//this is the forgot password component that allows users to reset their password using a recovery code
import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import './FormStyles.css'; 

// Component for handling forgot password functionality
const ForgotPassword = () => {
const [step, setStep] = useState(1); // 1: recovery code, 2: new password
const [formData, setFormData] = useState({
  username: '',
  recoveryCode: '',
  newPassword: '',
  confirmPassword: ''
});

// Loading state for async operations
const [loading, setLoading] = useState(false);
const [resetToken, setResetToken] = useState(null); 
const navigate = useNavigate();

// Handle input changes
const handleChange = e =>
  setFormData({ ...formData, [e.target.name]: e.target.value });

// Handle submission of recovery code
const handleCodeSubmit = async (e) => {
  e.preventDefault();
  setLoading(true);

  try {
    // Verify recovery code with backend
    const res = await fetch('/api/verify-recovery-code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: formData.username,
        recoveryCode: formData.recoveryCode.trim().toUpperCase()
      })
    });

  
    const data = await res.json();
    if (!data.success) throw new Error(data.message); // If verification fails, throw an error
    
    alert('Code verified! Please enter your new password.');
    setResetToken(data.resetToken); // Store the reset token
    setStep(2);
  } catch (error) {
    alert(error.message || 'Failed to verify code');
  } finally {
    setLoading(false);
  }
  
};

// Handle submission of new password
const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    
    // Check if passwords match
    if (formData.newPassword !== formData.confirmPassword) {
      alert('Passwords do not match');
      return;
    }
    
    // move to reset password
    setLoading(true);

    // try Call backend to reset password
    try {
      const res = await fetch('/api/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resetToken: resetToken,
          newPassword: formData.newPassword,
        })
      });

      const data = await res.json();
      if (!data.success) throw new Error(data.message);

      alert('Password reset successful! Please login with your new password.');
      sessionStorage.clear();
      // Redirect to login page after successful reset
      navigate('/customer-login');
    } catch (error) {
      //error restetting password
      alert(error.message || 'Error resetting password');
    } finally {
      setLoading(false); // End loading state
    }
  };

  return (
    <div className="form-container">
      <div className="form-card">
        <h2 className="form-title">Forgot Password</h2>

        {step === 1 && (
          <form onSubmit={handleCodeSubmit}>
            <p className="form-subtitle">Enter one of your recovery codes</p>
            <div className="form-group">
              <label>Username</label>
              <input
                type="text"
                name="username"
                placeholder="Your username"
                value={formData.username || ''}
                onChange={handleChange}
                className="form-input"
                required
              />
            </div>
            <div className="form-group">
              <label>Recovery Code</label>
              <input
                type="text"
                name="recoveryCode"
                placeholder="Enter recovery code"
                value={formData.recoveryCode}
                onChange={handleChange}
                className="form-input"
                maxLength="8"
                required
              />
            </div>
            <button type="submit" disabled={loading} className="form-button">
              {loading ? 'Verifying...' : 'Verify Code'}
            </button>
          </form>
        )}

        {step === 2 && (
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