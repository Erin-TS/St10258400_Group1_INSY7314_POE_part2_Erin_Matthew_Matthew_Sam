//this is the customer registration component so the customer can register
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
    cosnt [loading, setLoading] = useState(false);
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

        //registration to be implemented logic here
        console.log('Customer registration data:', formData);


        setTimeout(() => {
            alert('Registration successful! Please login.');
            //clear existing login data
            localStorage.removeItem('userType');
            localStorage.removeItem('isLoggedIn');

            //navigate to customer login after registration
            navigate('/CustomerLogin');
            setLoading(false);
        }, 2000); // Simulate a 2-second loading time
    };
    
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
