//this is the  employee login component so the customer can login
import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import './FormStyles.css';

const EmployeeLogin = () => {
    const[formData, setFormData] = useState({
        username: '',
        password: ''
    });

    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);

        //handle login logic here
        console.log('Customer login data:', formData);


        setTimeout(() => {
            localStorage.setItem('userType', 'employee');
            localStorage.setItem('isLoggedIn', 'false'); // Set true after OTP verification
            localStorage.setItem('employeeData', JSON.stringify(formData)); // Store employee data


        //after  login navigate to opt
        navigate('/otp', { state: { userType: 'employee', from: 'login' } });
      setLoading(false);
    }, 2000); // Simulate a 2-second loading time
    };

    return (
        <div className="form-container">
            <div className="form-card">
            <h2 className='form-title'>Employee Login</h2>
            <form onSubmit={handleSubmit}>
               
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
                
          <button type="submit" disabled={loading} className="form-button">
            {loading ? 'Logging in...' : 'Continue'}
          </button>

                <Link to="/forgot-password" className='forgot-password-link'>Forgot Password?</Link>

            </form>
        </div>
        </div>
    );
}
export default EmployeeLogin;