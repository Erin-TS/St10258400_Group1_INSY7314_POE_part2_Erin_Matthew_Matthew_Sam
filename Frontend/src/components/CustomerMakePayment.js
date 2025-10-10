import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './FormStyles.css';

// Customer Make Payment Component
const CustomerMakePayment = () => {
    const [formData, setFormData] = useState({
        amount: '',
        currency: '',
        provider: '',
        payeeFullName: '',
        payeeAccountNumber: '',
        bankName: '',
        payementReference: '',
        swiftCode: ''
    });

    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    //useEffect to check authentication and user type
    useEffect(() => {
        const isAuthenticated = sessionStorage.getItem('isAuthenticated');
        const userType = sessionStorage.getItem('userType');

        if (isAuthenticated !== 'true' || userType !== 'customer') {
            alert('Please login as a customer to access this page');
            navigate('/customer-login');
            return;
        }
    }, [navigate]);

    // Handle input changes with validation
    const handleChange = (e) => {
        const { name, value } = e.target;
        
        // Validate amount - only allow positive numbers with up to 2 decimal places
        if (name === 'amount') {
            if (value && !/^\d*\.?\d{0,2}$/.test(value)) {
                e.target.setCustomValidity('Amount should be a valid number with up to 2 decimal places');
                e.target.reportValidity();
                return; // Don't update state with invalid value
            } else {
                e.target.setCustomValidity('');
            }
        }
        
        // Validate and set custom  message
        if (name === 'bankName') {
            if (!/^[a-zA-Z\s&'-]*$/.test(value)) {
                e.target.setCustomValidity('Bank name should only contain letters, spaces, ampersands (&), hyphens (-), and apostrophes (\')');
            } else {
                e.target.setCustomValidity('');
            }
            e.target.reportValidity(); // Show the validation message immediately
        }
        
        // Validate and set custom message
        if (name === 'payeeAccountNumber') {
            if (!/^[0-9]*$/.test(value)) {
                e.target.setCustomValidity('Account number should only contain digits (0-9)');
            } else {
                e.target.setCustomValidity('');
            }
            e.target.reportValidity();
        }
        // Validate and set custom message
        
        if (name === 'payeeFullName') {
            if (!/^[a-zA-Z\s'-]*$/.test(value)) {
                e.target.setCustomValidity('Name should only contain letters, spaces, hyphens (-), and apostrophes (\')');
            } else {
                e.target.setCustomValidity('');
            }
            e.target.reportValidity();
        }

        // Validate and set custom message
        
        if (name === 'payementReference') {
            if (!/^[a-zA-Z0-9\s-]*$/.test(value)) {
                e.target.setCustomValidity('Reference should only contain letters, numbers, spaces, and hyphens (-)');
            } else {
                e.target.setCustomValidity('');
            }
            e.target.reportValidity();
        }
        
        setFormData({
            ...formData,
            [name]: value
        });
    };

    // Handle form submission
    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
       try {
        // Client-side validation
        const response = await fetch('/api/payments', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify(formData)
        });

        const data = await response.json();
        if (response.ok && data.success) {
            alert('Payment successful! Reference: ' + data.reference);

            // Clear form
            setFormData({
                amount: '',
                currency: '',
                provider: '',
                payeeFullName: '',
                payeeAccountNumber: '',
                bankName: '',
                payementReference: '',
                swiftCode: ''
            });
        } else {
            alert(data.error || 'Payment failed. Please try again.');
        }
         } catch (error) {
            console.error('Payment error:', error);
            alert('An error occurred during payment. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    // Handle logout
    const handleLogout = async () => {
        try {
            await fetch('/api/logout', { 
                method: 'POST',
                credentials: 'include'
            });
        } catch (error) {
            console.error('Logout error:', error);
        }
        sessionStorage.clear();
        navigate('/customer-login');
    }

    return (
        <div className="form-container">
            <div className="form-card payment-card">
                <div className="hearder-with-logout">
                <h2>Make Payment</h2>
                <button onClick={handleLogout} className="logout-button">
                    Logout
                </button>
                </div>

                <form onSubmit={handleSubmit}>
                    <div className='form-group'>
                        <label>Amount:</label>
                        <input
                            type="text"
                            name="amount"
                            value={formData.amount}
                            onChange={handleChange}
                            className='form-input'
                            pattern="^\d+(\.\d{1,2})?$"
                            title="Amount must be a valid number (e.g., 10 or 10.50)"
                            required
                        />
                    </div>  
                    <div className='form-group'>
                        <label>Currency:</label>
                        <select
                            name="currency"
                            value={formData.currency}
                            onChange={handleChange}
                            className='form-input'
                            required
                        >
                            <option value="">Select Currency</option>
                            <option value="USD">USD</option>
                            <option value="EUR">EUR</option>
                            <option value="GBP">GBP</option>
                            <option value="AUD">AUD</option>
                            <option value="CAD">CAD</option>
                            <option value="NZD">NZD</option>
                            <option value="ZAR">ZAR</option>
                            <option value="RUB">RUB</option>
                            
                            </select>
                    </div>
                    <div className='form-group'>
                        <label>Payment Provider:</label>
                        <select
                            name="provider"
                            value={formData.provider}
                            onChange={handleChange}
                            className='form-input'
                            required
                        >
                            <option value="">Select Provider</option>
                            <option value="Swift">Swift</option>
                            <option value="Western Union">Western Union</option>
                            <option value="MoneyGram">MoneyGram</option>
                            <option value="PayPal">PayPal</option>

                            </select>
                    </div>
                    <div className='form-group'>
                        <label>Payee Full Name:</label>
                        <input
                            type="text"
                            name="payeeFullName"
                            value={formData.payeeFullName}
                            onChange={handleChange} 
                            className='form-input'
                            required
                            pattern="^[a-zA-Z\s'-]{2,100}$"
                            title="Name should contain only letters, spaces, hyphens, and apostrophes (2-100 characters)"
                            maxLength="100"
                        />
                    </div>
                    <div className='form-group'>
                        <label>Payee Account Number:</label>
                        <input
                            type="text"
                            name="payeeAccountNumber"
                            value={formData.payeeAccountNumber}
                            onChange={handleChange}
                            className='form-input'  
                            required
                            pattern="^[0-9]{8,20}$"
                            title="Account number should be 8-20 digits"
                            maxLength="20"
                        />
                    </div>       
                    <div className='form-group'>
                        <label>Bank Name:</label>
                        <input  
                            type="text"
                            name="bankName"
                            value={formData.bankName}
                            onChange={handleChange}
                            className='form-input'
                            required
                            pattern="^[a-zA-Z\s&'-]{2,100}$"
                            title="Bank name should only contain letters, spaces, ampersands (&), hyphens (-), and apostrophes ('). No special characters like @ are allowed."
                            maxLength="100"
                        />
                    </div>
                    <div className='form-group'>
                        <label>Payment Reference:</label>
                        <input
                            type="text"
                            name="payementReference"
                            value={formData.payementReference}
                            onChange={handleChange}
                            className='form-input'
                            required
                            pattern="^[a-zA-Z0-9\s-]{3,50}$"
                            title="Reference should be 3-50 characters (letters, numbers, spaces, hyphens)"
                            maxLength="50"
                        />
                    </div>
                    <div className='form-group'>
                        <label>SWIFT Code:</label>
                        <input
                            type="text"
                            name="swiftCode"
                            value={formData.swiftCode}         
                            onChange={handleChange}
                            className='form-input'
                            required
                            maxLength="11"
                            
                            pattern="[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?"       
                            title="SWIFT code must be 8 or 11 characters long, with the first 6 letters being uppercase letters, followed by 2 alphanumeric characters, and an optional 3 alphanumeric characters."
                        />
                    </div>

                      <button type="submit" disabled={loading} className="form-button">
            {loading ? 'Processing...' : 'Make Payment'}
          </button>
                </form>
            </div>
        </div>
    );
};

export default CustomerMakePayment;