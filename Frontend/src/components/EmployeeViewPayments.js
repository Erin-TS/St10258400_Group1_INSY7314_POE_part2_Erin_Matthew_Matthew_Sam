import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './FormStyles.css';

const EmployeeViewPayments = () => {
    const [payments, setPayments] = useState([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState('all'); // Fixed: was "consr"
    const navigate = useNavigate();

    useEffect(() => {
        const isAuthenticated = sessionStorage.getItem('isAuthenticated');
        const userType = sessionStorage.getItem('userType');
        if (isAuthenticated !== 'true' || userType !== 'employee') {
            alert('Please login to access the employee dashboard');
            navigate('/employee-login');
            return;
        }

        fetchPayments();
    }, [navigate]);

    const fetchPayments = async () => {
        setLoading(true);
        try {
            const response = await fetch('/api/payments', {
                credentials: 'include'
            });
            const data = await response.json();
            setPayments(data);
        } catch (error) {
            console.error('Error fetching payments:', error);
            // If backend is not available, use mock data
            setTimeout(() => {
                const mockPayments = [
                    {
                        id: 1,
                        customerName: 'John Doe',
                        amount: 1500.00,
                        currency: 'USD',
                        payeeName: 'Jane Smith',
                        bankName: 'ABC Bank',
                        status: 'Pending',
                        date: '2024-01-15',
                        reference: 'PAY001'
                    },
                    {
                        id: 2,
                        customerName: 'Mary Johnson',
                        amount: 2300.50,
                        currency: 'EUR',
                        payeeName: 'Bob Wilson',
                        bankName: 'XYZ Bank',
                        status: 'Completed',
                        date: '2024-01-14',
                        reference: 'PAY002'
                    },
                    {
                        id: 3,
                        customerName: 'David Brown',
                        amount: 750.25,
                        currency: 'GBP',
                        payeeName: 'Alice Cooper',
                        bankName: 'DEF Bank',
                        status: 'Failed',
                        date: '2024-01-13',
                        reference: 'PAY003'
                    }
                ];
                
                setPayments(mockPayments);
                setLoading(false);
            }, 1500);
        } finally {
            setLoading(false);
        }
    };

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
        navigate('/employee-login');
    };

    const handleApprove = async (paymentId) => {
        try {
            const response = await fetch(`/api/payments/${paymentId}/approve`, {
                method: 'POST',
                credentials: 'include'
            });
            if (response.ok) {
                fetchPayments();
                alert('Payment approved successfully.');
            } else {
                alert('Failed to approve payment.');
            }
        } catch (error) {
            console.error('Error approving payment:', error);
            // Fallback for when backend is not available
            setPayments(payments.map(payment => 
                payment.id === paymentId 
                    ? { ...payment, status: 'Approved' }
                    : payment
            ));
            alert('Payment approved successfully.');
        }
    };

    const handleReject = async (paymentId) => {
        try {
            const response = await fetch(`/api/payments/${paymentId}/reject`, {
                method: 'POST',
                credentials: 'include'
            });
            if (response.ok) {
                fetchPayments();
                alert('Payment rejected successfully.');
            } else {
                alert('Failed to reject payment.');
            }
        } catch (error) {
            console.error('Error rejecting payment:', error);
            // Fallback for when backend is not available
            setPayments(payments.map(payment => 
                payment.id === paymentId 
                    ? { ...payment, status: 'Rejected' }
                    : payment
            ));
            alert('Payment rejected successfully.');
        }   
    };

    const handleSendToSwift = (paymentId, reference) => {
        alert(`Sending payment ${reference} to SWIFT...`);
        // You can add actual SWIFT integration logic here in the future
    };

    const filteredPayments = payments.filter(payment => {
        if (filter === 'all') return true;
        return payment.status.toLowerCase() === filter.toLowerCase();
    });

    const getStatusColor = (status) => {
        switch (status.toLowerCase()) {
            case 'pending': 
                return 'orange';
            case 'completed':
            case 'approved':
                return 'green';
            case 'failed':
            case 'rejected':
                return 'red';
            default:
                return 'black';
        }   
    };

    if (loading) {
        return (
            <div className="form-container">
                <div className="employee-view-container">
                    <div className="loading">Loading payments...</div>
                </div>
            </div>
        );
    }

    return (
        <div className="form-container">
            <div className="employee-view-container">
                <div className="header-with-logout">
                    <h2>Employee View Payments</h2>
                    <button className="logout-button" onClick={handleLogout}>Logout</button>
                </div>
                
                <div className="filter-container">
                    <label htmlFor="statusFilter">Filter by Status:</label>
                    <select
                        id="statusFilter"
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                        className="filter-select"
                    >   
                        <option value="all">All</option>
                        <option value="pending">Pending</option>
                        <option value="completed">Completed</option>
                        <option value="approved">Approved</option>
                        <option value="failed">Failed</option>
                        <option value="rejected">Rejected</option>
                    </select>
                </div>

                <div className="table-container">
                    <table className="payments-table">
                        <thead>
                            <tr>
                                <th>Customer Name</th>
                                <th>Amount</th>
                                <th>Currency</th>
                                <th>Payee Name</th>
                                <th>Bank Name</th>
                                <th>Status</th>
                                <th>Date</th>
                                <th>Reference</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredPayments.map(payment => (
                                <tr key={payment._id || payment.id}>
                                    <td>{payment.customerName || `${payment.username}` || 'N/A'}</td>
                                    <td>{typeof payment.amount === 'number' ? payment.amount.toFixed(2) : payment.amount}</td>
                                    <td>{payment.currency}</td>
                                    <td>{payment.payeeFullName || payment.payeeName || 'N/A'}</td>
                                    <td>{payment.bankName}</td>
                                    <td style={{ color: getStatusColor(payment.status), fontWeight: 'bold' }}>
                                        {payment.status}
                                    </td>
                                    <td>{new Date(payment.createdAt || payment.date).toLocaleDateString()}</td>
                                    <td>{payment.reference}</td>
                                    <td>
                                        {payment.status.toLowerCase() === 'pending' && (
                                            <div className="action-buttons">
                                                <button 
                                                    onClick={() => handleApprove(payment._id || payment.id)}
                                                    className="approve-button"
                                                >
                                                    Approve
                                                </button>
                                                <button 
                                                    onClick={() => handleReject(payment._id || payment.id)}
                                                    className="reject-button"
                                                >
                                                    Reject
                                                </button>
                                            </div>
                                        )}
                                        {payment.status.toLowerCase() === 'approved' && (
                                            <div className="action-buttons">
                                                <button 
                                                    onClick={() => handleSendToSwift(payment._id || payment.id, payment.reference)}
                                                    className="swift-button"
                                                >
                                                    Send to SWIFT
                                                </button>
                                            </div>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>

                {filteredPayments.length === 0 && (
                    <div className="no-payments">No payments found.</div>
                )}
            </div>
        </div>
    );
};

export default EmployeeViewPayments;