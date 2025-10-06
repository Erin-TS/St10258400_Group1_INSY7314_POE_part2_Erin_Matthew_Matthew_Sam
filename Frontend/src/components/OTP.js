import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import './FormStyles.css';

const OTP = () => {
    const [otpValue, setOtpValue] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [userType, setUserType] = useState(sessionStorage.getItem('userType') || '');
    const navigate = useNavigate();
    const location = useLocation();

useEffect(() => {
    const typeFromState = location.state?.userType;
    const typeFromStorage = sessionStorage.getItem('userType');

    if (typeFromState) {
        setUserType(typeFromState);
    } else if (typeFromStorage) {
        setUserType(typeFromStorage);
    }else {
        navigate('/');
    }
}, [location.state, navigate]); 


    const handleSubmit =  async(e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const response = await fetch('/api/verify-totp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include',
                body: JSON.stringify({ token: otpValue })
            });
            const data = await response.json();
            if (response.ok && data.success ) {
                
            sessionStorage.setItem('isAuthenticated', 'true');
            
        if(userType === 'customer') {
            navigate('/customer-make-payment');
        } else if (userType === 'employee') {
            navigate('/employee-view-payments');
        }else {
            navigate('/');
        }
    } else {
        setError(data.error || 'OTP verification failed. Please try again.');
    }
        } catch (error) {
            console.error('OTP verification error:', error);
            setError('OTP verification failed. Please try again.');
        }finally {
            setLoading(false);
        }
    };


    return (
        <div className="form-container">
            <div className="form-card otp-card">
                <h2>Enter TOTP</h2>
                <p className='form-subtitle'>
                    Please enter the 6-digit code from your authenticator app.
                </p>
                <form onSubmit={handleSubmit}>
                    <div className='form-group'>
                        <label>TOTP:</label>
                        <input
                            type="text"
                            name="otp"
                            value={otpValue}
                            onChange={(e) => {
                                const value = e.target.value.replace(/\D/g, ''); // Remove non-digit characters
                                if (value.length <= 6) {
                                    setOtpValue(value);
                                    setError('');
                                }
                            } }
                            className='form-input'
                            placeholder='000000'
                            maxLength="6"
                            pattern="\d{6}"
                            required
                            autoComplete='off' />
                    </div>
                    {error && <p className="error-message">{error}</p>}
                    <button type="submit" disabled={loading} className="form-button">
                        {loading ? 'Verifying...' : 'Login'}
                    </button>
                </form>
            </div>
            </div>

    );
};

export default OTP;