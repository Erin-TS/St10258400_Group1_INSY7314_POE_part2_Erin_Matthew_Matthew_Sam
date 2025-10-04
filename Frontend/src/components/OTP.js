import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import './FormStyles.css';
import RecoveryCodes from './RecoveryCodes';

const OTP = () => {
    const [otpValue, setOtpValue] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [userType, setUserType] = useState(localStorage.getItem('userType') || '');
    const [showRecoveryCodes, setShowRecoveryCodes] = useState(false);
    const [recoveryCodes, setRecoveryCodes] = useState([]);
    const navigate = useNavigate();
    const location = useLocation();

useEffect(() => {
    //get user type from local storage or navigation state
    const typeFromState = location.state?.userType;
    const typeFromStorage = localStorage.getItem('userType');

    if (typeFromState) {
        setUserType(typeFromState);
    } else if (typeFromStorage) {
        setUserType(typeFromStorage);
    }else {
        //return to home if no user type found
        navigate('/'); // Redirect to home
    }
}, [location.state, navigate]); 


    const handleSubmit =  async(e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        //totp verification logic 
        try {
            const token = localStorage.getItem('token');

            const response = await fetch('/api/verify-totp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ token: otpValue })
            });
            const data = await response.json();
            if (response.ok && data.success ) {
            

            // check if user needs recovery codes
            if (data.needsRecoveryCodes) {
                    const recoveryResponse = await fetch('/api/generate-recovery-codes', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${token}`
                        }
                    });

                    const recoveryData = await recoveryResponse.json();

                    if (recoveryResponse.ok && recoveryData.success) {
                        // show recovery codes page
                        setRecoveryCodes(recoveryData.codes);
                        setShowRecoveryCodes(true); // THIS OPENS THE PAGE
                        setLoading(false);
                        return; 
                    } else {
                        setError(recoveryData.message || 'Failed to generate recovery codes.');
                    }
                }

                localStorage.setItem('isLoggedIn', 'true'); // Set user as logged in after OTP verification
            
        //navigate to page based on user type
        if(userType === 'customer') {
            navigate('/customer-make-payment');
        } else if (userType === 'employee') {
            navigate('/employee-view-payments');
        }else {
            navigate('/'); // Redirect to home if userType is invalid
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

        //  HANDLE MODAL CLOSE
    const handleCloseModal = () => {
        setShowRecoveryCodes(false);
        // Modal handles navigation to dashboard
    };

    return (
        <><div className="form-container">
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
        </div><RecoveryCodes
                isOpen={showRecoveryCodes}
                codes={recoveryCodes}
                onClose={handleCloseModal} />
                </>

    );
};

export default OTP;