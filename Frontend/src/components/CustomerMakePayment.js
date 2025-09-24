import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './FormStyles.css';

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

    useEffect(() => {
        //check if user is logged in and is a customer
        const isLoggedIn = localStorage.getItem('isLoggedIn');
        const userType = localStorage.getItem('userType');

        if (!isLoggedIn || userType !== 'customer') {
            alert('Please login as a customer to access this page');
            navigate('/CustomerLogin');
            return;
        }
    }, [navigate]);

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        setLoading(true);
        //payment logic to be implemented here
        console.log('Customer Make Payment data:', formData);

        setTimeout(() => {
            alert('Payment successful! it will be processsed shortly.');

            //reset form
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
            setLoading(false);
        }, 2000); // Simulate a 2-second loading time
    };

    const handleLogout = () => {
        localStorage.removeItem('isLoggedIn');
        localStorage.removeItem('userType');
        navigate('/CustomerLogin');
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
                            type="number"
                            name="amount"
                            value={formData.amount}
                            onChange={handleChange}
                            className='form-input'
                            step="0.01"
                            min="0.01"
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