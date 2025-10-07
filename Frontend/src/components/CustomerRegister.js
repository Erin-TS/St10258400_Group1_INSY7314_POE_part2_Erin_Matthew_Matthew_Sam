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
    const [showRecoveryCodes, setShowRecoveryCodes] = useState(false); 
    const [recoveryCodes, setRecoveryCodes] = useState([]);
    const [codesSaved, setCodesSaved] = useState(false);
    const [copySuccess, setCopySuccess] = useState(false);
    const [downloadSuccess, setDownloadSuccess] = useState(false);
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

    const handleContinueToRecoveryCodes = async () => {
        setLoading(true);
        try {

            const response = await fetch('/api/generate-recovery-codes', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ userId: qrCodeData.userId })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                setRecoveryCodes(data.codes);
                setShowQRCode(false);
                setShowRecoveryCodes(true);
            } else {
                alert(data.message || 'Failed to generate recovery codes');
            }
            
        } catch (error) {
            console.error('Recovery codes error:', error);
            alert('Failed to generate recovery codes');
        } finally {
            setLoading(false);
        }
    }

    const handleCopyToClipboard = async () => {
        try {
            const codesText = recoveryCodes.join('\n');
            await navigator.clipboard.writeText(codesText);
            setCopySuccess(true);
            setCodesSaved(true);
            
            setTimeout(() => setCopySuccess(false), 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
            alert('Failed to copy codes. Please try downloading instead.');
        }
    };

    const handleDownloadCodes = () => {
        const codesText = recoveryCodes.join('\n');
        const blob = new Blob([
            'RECOVERY CODES - KEEP SAFE\n',
            '================================\n\n',
            codesText,
            '\n\n================================\n',
            'Each code can only be used once.\n',
            'Store in a secure location.\n',
            `Generated: ${new Date().toLocaleString()}`
        ], { type: 'text/plain' });

        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `recovery-codes-${Date.now()}.txt`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        setDownloadSuccess(true);
        setCodesSaved(true);
        
        setTimeout(() => setDownloadSuccess(false), 2000);
    };
    
    const handleContinueToLogin = () => {
        if (!codesSaved) {
            alert('Please save your recovery codes before continuing!');
            return;
        }

        alert('Registration successful! Please login.');
                sessionStorage.clear();
                window.location.href = '/customer-login'; 
    };

    // Show Recovery Codes Section
    if (showRecoveryCodes && recoveryCodes.length > 0) {
        return (
            <div className="form-container">
                <div className="form-card register-card">
                    <h2>Your Recovery Codes</h2>
                    <div className="warning-banner">
                        <strong>Important: Save These Codes!</strong>
                        <p>These codes can be used to recover your account if you lose access to your authenticator app. 
                            Each code can only be used once. Store them in a safe place.</p>
                    </div>

                    <div className="">
                        {recoveryCodes.map((code, index) => (
                            <div key={index} className="code-item">
                                {code}
                            </div>
                        ))}
                    </div>

                    <div className="">
                        <button 
                            onClick={handleCopyToClipboard}
                            className={`form-button ${copySuccess ? 'success' : ''}`}
                        >
                            {copySuccess ? 'Copied!' : 'Copy to Clipboard'}
                        </button>
                        <button 
                            onClick={handleDownloadCodes}
                            className={`form-button ${downloadSuccess ? 'success' : ''}`}
                        >
                            {downloadSuccess ? 'Downloaded!' : 'Download Codes'}
                        </button>
                    </div>

                    <button 
                        onClick={handleContinueToLogin}
                        className="form-button primary"
                        disabled={!codesSaved}
                    >
                        Continue to Login
                    </button>

                    <p className="save-instructions">
                        {codesSaved 
                            ? 'Recovery codes saved! You can now continue.' 
                            : 'Please download or copy your recovery codes to continue'}
                    </p>
                </div>
            </div>
        );
    }

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
                    <button onClick={handleContinueToRecoveryCodes} className="form-button">
                        Continue to Recovery Codes
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
                    onChange={(e) => {
                        const digits = e.target.value.replace(/\D/g, '').slice(0, 13);
                        setFormData({ ...formData, idNumber: digits });
                    }}
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
                    onChange={(e) => {
                        const digits = e.target.value.replace(/\D/g, '').slice(0, 10);
                        setFormData({ ...formData, accountNumber: digits });
                    }}
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
                    pattern="^[A-Za-z0-9_]{3,20}$"
                    title="Username: 3-20 characters, letters, numbers, and underscores only"
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
