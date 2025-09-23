//this file is the main app component
import React from 'react';
import './App.css';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Home from './components/Home';
import CustomerLogin from './components/CustomerLogin';
import CustomerRegister from './components/CustomerRegister';
import AdminLogin from './components/AdminLogin';
import UserOtp from './components/UserOtp';
import ResetPassword from './components/ResetPassword';
import CustomerMakePayment from './components/CustomerMakePayment';
import AdminViewPayments from './components/AdminDashboard';
import NotFound from './components/NotFound';

function App() {
  return (
    <Router>
        <div className="App">
            <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/customer-login" element={<CustomerLogin />} />
                <Route path="/customer-register" element={<CustomerRegister />} />
                <Route path="/admin-login" element={<AdminLogin />} />
                <Route path="/user-otp" element={<UserOtp />} />
                <Route path="/reset-password" element={<ResetPassword />} />
                <Route path="/customer-make-payment" element={<CustomerMakePayment />} />
                <Route path="/admin-view-payments" element={<AdminViewPayments />} />
                <Route path="*" element={<NotFound />} />
            </Routes>
        </div>
    </Router>
  );
}
export default App;