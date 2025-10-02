import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './FormStyles.css';

const CustomerRegister = () => {
    const [formData, setFormData] = useState({
        firstName: '',
        lastName: '',
        idNumber: '',
        accountNumber: '',
        username: '',
        password: '',
        confirmPassword: ''
    });

    const [captchaChecked, setCaptchaChecked] = useState(false);
    const [loading, setLoading] = useState(false);
    const [showQRCode, setShowQRCode] = useState(false);
    const [qrCodeData, setQrCodeData] = useState(null);
    const navigate = useNavigate();

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if(!captchaChecked) {
            alert('Please complete the CAPTCHA to verify you are not a robot');
            return;
        }

        if(formData.password !== formData.confirmPassword) {
            alert('Passwords do not match');
            return;
        }

        setLoading(true);

        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    firstName: formData.firstName,
                    lastName: formData.lastName,
                    idNumber: formData.idNumber,
                    accountNumber: formData.accountNumber,
                    username: formData.username,
                    password: formData.password
                })
            });

            const data = await response.json();

            if (response.ok) {
                setQrCodeData(data);
                setShowQRCode(true);
                
            } else {
                alert(data.error || 'Registration failed');
            }
        } catch (error) {
            alert('Registration failed');
        } finally {
            setLoading(false);
        }
    };
    
    const handleContinueToLogin = () => {
        alert('Registration successful! Please login.');
                //clear existing login data
                localStorage.removeItem('userType');
                localStorage.removeItem('isLoggedIn');

                //navigate to customer login after registration
                navigate('/customer-login');
    };

    if (showQRCode && qrCodeData) {
        return (
            <div className="qr-code-container">
                <div className="form-card register-card">
                    <h2>Scan the QR Code to set up TOTP for MFA</h2>
                    <p className = "form-subtitle">
                        Please scan the QR code with your authenticator app to set up TOTP for multi-factor authentication.
                        <br/> You can use apps like Google Authenticator, Authy, or Microsoft Authenticator.
                    </p>
                    <div className="qr-code-container">
                        <img src={qrCodeData.qrCode} alt="TOTP QR Code" className="qr-code-image" />
                    </div>
                    <div className="manual-setup">
                        <p><strong>Manual Code Entry:</strong></p>
                        <code className="secret-code">{qrCodeData.secret}</code>
                        <p className="help-text">
                            If you cannot scan the QR code, you can manually enter the above code into your authenticator app.
                        </p>
                    </div>
                    <button onClick={handleContinueToLogin} className="form-button">
                        Continue to Login
                    </button>
                </div>    
            </div>
        );
      
    }

    return (
        <div className="form-container">
            <div className="form-card register-card">
            <h2>Customer Registration</h2>
            <form onSubmit={handleSubmit}>
                <div className='form-group'>
                <label>First Name:</label>
                <input
                    type="text"
                    name="firstName"
                    value={formData.firstName}
                    onChange={handleChange}
                    className='form-input'
                    required
                />
                </div>
                <div className='form-group'>
                <label>Last Name:</label>
                <input
                    type="text"
                    name="lastName"
                    value={formData.lastName}
                    onChange={handleChange}
                    className='form-input'
                    required
                />
                </div>
                <div className='form-group'>
                <label>ID Number:</label>
                <input
                    type="text"
                    name="idNumber"
                    value={formData.idNumber}
                    onChange={handleChange}
                    className='form-input'
                    required
                    maxLength="13"
                    minLength="13"
                    pattern="\d{13}"
                    title="ID Number must be 13 digits"
                />
                </div>
                <div className='form-group'>
                <label>Account Number:</label>
                <input

                    type="text"
                    name="accountNumber"
                    value={formData.accountNumber}
                    onChange={handleChange}
                    className='form-input'
                    required
                    maxLength="10"
                    minLength="10"
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
                    minLength="8"
                    pattern='(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@$!%*#?&]).{8,}'
                    title="Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character"
                />
                </div>
                <div className='form-group'>
                <label>Confirm Password:</label>
                <input
                    type="password"
                    name="confirmPassword"
                    value={formData.confirmPassword}
                    onChange={handleChange}
                    className='form-input'
                    required
                    />
                </div>
               <div className="captcha-container">
            <input
              type="checkbox"
              id="captcha"
              checked={captchaChecked}
              onChange={(e) => setCaptchaChecked(e.target.checked)}
            />
            <label htmlFor="captcha" className="captcha-label">
              I'm not a robot
            </label>
            <div className="captcha-icon">🔒</div>
          </div>

          <button type="submit" disabled={loading} className="form-button">
            {loading ? 'Registering...' : 'Register'}
          </button>
            </form>
            </div>
        </div>
    );
};
export default CustomerRegister;
