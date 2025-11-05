// this is the employee login component
import React, { useState } from 'react';
import { useNavigate ,Link} from 'react-router-dom';
import './FormStyles.css';

// EmployeeLogin component
const EmployeeLogin = () => {
    const[formData, setFormData] = useState({
        username: '',
        password: ''
    });

    // Loading state
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    // Handle input changes
    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    // Handle form submission
    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);

        try {
            //call the login API
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(
                    { username: formData.username, password: formData.password }
                ), 
            });

            const data = await response.json(); //pass response data

            // If login is successful, store user data and navigate to OTP page
            if (response.ok) {
                sessionStorage.setItem('userType', 'employee');
                sessionStorage.setItem('isAuthenticated', 'pending');
                sessionStorage.setItem('user', JSON.stringify(data.user));
                navigate('/otp', { state: { userType: 'employee', from: 'login' } });
            } else {
                alert(data.error || 'Login failed'); // Show error message
            }
        } catch (error) {
            //login error
            console.error('Login error:', error);
            alert('An error occurred during login');
        } finally {
            setLoading(false); // End loading state
        }
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