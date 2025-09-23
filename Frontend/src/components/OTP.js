//thia ia the OTP component so the customer and employee can enter the OTP sent to them to
// verify their identity so the login process can be completed

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './FormStyles.css';

const OTP = () => {
    const [otpValue, setOtpValue] = useState('');
    const [loading, setLoading] = useState(false);
    const [userType, setUserType] = useState(localStorage.getItem('userType') || '');
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


    const handleChange = (e) => {
        e.preventDefault();
        setLoading(true);


        //implement otp logic here

        console.log('OTP entered:',{ otp: otpValue,  userType});

        setTimeout(() => {
            localStorage.setItem('isLoggedIn', 'true'); // Set user as logged in after OTP verification

        //navigate to page based on user type
        if(userType === 'customer') {
            navigate('/CustomerMakePayment');
        } else if (userType === 'employee') {
            navigate('/EmployeeViewPayments');
        }else {
            navigate('/'); // Redirect to home if userType is invalid
        }
        setLoading(false);
        }, 2000); // Simulate a 2-second loading time
    };

    return (
        <div className="form-container">
            <div className="form-card otp-card">
            
            <h2>Enter OTP</h2>
            <form onSubmit={handleChange}>
                <div className='form-group'>
                <label>OTP:</label>
                <input
                    type="text"
                    name="otp"
                    value={otpValue}
                    onChange={(e) => setOtpValue(e.target.value)}
                    className='form-input'
                    maxLength="6"
                    minLength="6"
                    pattern="\d{10}"
                    required
                />
                </div>
             <button type="submit" disabled={loading} className="form-button">
            {loading ? 'Verifying...' : 'Login'}
          </button>
            </form>
            </div>
        </div>
    );
};

export default OTP;