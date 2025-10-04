import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './FormStyles.css';

const RecoveryCodes = ({ isOpen, codes, onClose }) => { // ← Add props here
    const [codesSaved, setCodesSaved] = useState(false); // ← Was missing
    const [copySuccess, setCopySuccess] = useState(false);
    const [downloadSuccess, setDownloadSuccess] = useState(false);
    const navigate = useNavigate();

    // Reset state when modal opens
    useEffect(() => {
        if (isOpen) {
            setCodesSaved(false);
            setCopySuccess(false);
            setDownloadSuccess(false);
        }
    }, [isOpen]);

    const handleCopyToClipboard = async () => {
        try {
            const codesText = codes.join('\n');
            await navigator.clipboard.writeText(codesText);
            setCopySuccess(true);
            setCodesSaved(true);
            
            setTimeout(() => setCopySuccess(false), 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
            alert('Failed to copy codes. Please try downloading instead.');
        }
    };

    const handleDownloadCodes = () => {
        const codesText = codes.join('\n');
        const blob = new Blob([
            'RECOVERY CODES - KEEP SAFE\n',
            '================================\n\n',
            codesText,
            '\n\n================================\n',
            'Each code can only be used once.\n',
            'Store in a secure location.\n',
            `Generated: ${new Date().toLocaleString()}`
        ], { type: 'text/plain' });

        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `recovery-codes-${Date.now()}.txt`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        setDownloadSuccess(true);
        setCodesSaved(true);
        
        setTimeout(() => setDownloadSuccess(false), 2000);
    };

    const handleDone = () => {
        if (!codesSaved) {
            alert('⚠️ Please save your recovery codes before continuing!');
            return;
        }

        localStorage.setItem('isLoggedIn', 'true'); // Set user as logged in afte saving codes

        onClose(); // Close modal
        
        // Navigate to dashboard
        const userType = localStorage.getItem('userType');
        if (userType === 'customer') {
            navigate('/customer-make-payment');
        } else if (userType === 'employee') {
            navigate('/employee-view-payments');
        } else {
            navigate('/');
        }
    };

    // Don't render if not open
    if (!isOpen) return null;

    return (
        <div className="modal-overlay"> {/* ← Changed from form-container */}
            <div className="modal-content recovery-modal">
                <div className="modal-header">
                    <h2>🔐 Your Recovery Codes</h2>
                </div>

                <div className="warning-banner">
                    <strong>⚠️ Important: Save These Codes!</strong>
                    <p>These codes can be used to recover your account if you lose access to your authenticator app. Each code can only be used once. Store them in a safe place.</p>
                </div>

                <div className="codes-grid">
                    {codes.map((code, index) => (
                        <div key={index} className="code-item">
                            {code}
                        </div>
                    ))}
                </div>

                <div className="modal-actions">
                    <button 
                        onClick={handleCopyToClipboard}
                        className={`form-button ${copySuccess ? 'success' : ''}`}
                    >
                        {copySuccess ? '✓ Copied!' : '📋 Copy to Clipboard'}
                    </button>
                    <button 
                        onClick={handleDownloadCodes}
                        className={`form-button ${downloadSuccess ? 'success' : ''}`}
                    >
                        {downloadSuccess ? '✓ Downloaded!' : '💾 Download Codes'}
                    </button>
                </div>

                <button 
                    onClick={handleDone}
                    className="form-button primary"
                    disabled={!codesSaved}
                    style={{ 
                        opacity: codesSaved ? 1 : 0.5, 
                        cursor: codesSaved ? 'pointer' : 'not-allowed',
                        width: '100%',
                        marginTop: '10px'
                    }}
                >
                    ✓ Done - Continue to Dashboard
                </button>

                <p className="save-instructions">
                    {codesSaved 
                        ? '✓ Recovery codes saved! You can now continue.' 
                        : 'Please download or copy your recovery codes to continue'}
                </p>
            </div>
        </div>
    );  
}

export default RecoveryCodes;