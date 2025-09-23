//this file is the main app component
import React from 'react';
import './App.css';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Home from './components/Home.js';
import CustomerLogin from './components/CustomerLogin.js';
import CustomerRegister from './components/CustomerRegister.js';
import EmployeeLogin from './components/EmployeeLogin.js';
import Otp from './components/OTP.js';
import ForgotPassword from './components/ForgotPassword.js';
import CustomerMakePayment from './components/CustomerMakePayment.js';
import EmployeeViewPayments from './components/EmployeeViewPayments.js';
import NotFound from './components/NotFound.js';

function App() {
  return (
    <Router>
        <div className="App">
            <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/customer-login" element={<CustomerLogin />} />
                <Route path="/customer-register" element={<CustomerRegister />} />
                <Route path="/employee-login" element={<EmployeeLogin />} />
                <Route path="/otp" element={<Otp />} />
                <Route path="/forgot-password" element={<ForgotPassword />} />
                <Route path="/customer-make-payment" element={<CustomerMakePayment />} />
                <Route path="/employee-view-payments" element={<EmployeeViewPayments />} />
                <Route path="*" element={<NotFound />} />
            </Routes>
        </div>
    </Router>
  );
}
export default App;