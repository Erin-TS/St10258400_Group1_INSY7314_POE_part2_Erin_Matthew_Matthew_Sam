//thia ia the OTP component so the customer and employee can enter the OTP sent to them to
// verify their identity so the login process can be completed

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './FormStyles.css';

const OTP = () => {
    const [otpValue, setOtpValue] = useState('');
    const navigate = useNavigate();
    const handleChange = (e) => {
        e.preventDefault();


        //implement otp logic here

        console.log('OTP entered:', otpValue);

        //navigate to page based on user type
        navigate('/CustomerMakePayment');
        //navigate('/EmployeeViewPayments');
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
                <button type="submit" className='form-button'>Login</button>
            </form>
            </div>
        </div>
    );
};

export default OTP;