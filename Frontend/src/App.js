//this file is the main app component
import React from 'react';
import './App.css';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Home from './components/Home';
import CustomerLogin from './components/CustomerLogin';
import CustomerRegister from './components/CustomerRegister';
import EmployeeLogin from './components/EmployeeLogin';
import Otp from './components/Otp';
import ForgotPassword from './components/ForgotPassword';
import CustomerMakePayment from './components/CustomerMakePayment';
import EmployeeViewPayments from './components/AdminDashboard';
import NotFound from './components/NotFound';

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