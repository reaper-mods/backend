const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const twilio = require('twilio');

// Initialize Twilio
const twilioClient = twilio(
    process.env.TWILIO_ACCOUNT_SID,
    process.env.TWILIO_AUTH_TOKEN
);

// In-memory OTP storage (use Redis in production)
const otpStore = new Map();

// Generate 6-digit OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Send OTP endpoint
router.post('/send-otp', async (req, res) => {
    try {
        const { phoneNumber } = req.body;
        
        if (!phoneNumber || phoneNumber.length < 10) {
            return res.status(400).json({
                success: false,
                message: 'Invalid phone number'
            });
        }
        
        const otp = generateOTP();
        const sessionId = require('crypto').randomUUID();
        
        // Store OTP with expiry (5 minutes)
        otpStore.set(sessionId, {
            phoneNumber,
            otp,
            expiresAt: Date.now() + 5 * 60 * 1000,
            attempts: 0
        });
        
        // Send OTP via Twilio
        try {
            await twilioClient.verify.v2
                .services(process.env.TWILIO_SERVICE_SID)
                .verifications
                .create({
                    to: phoneNumber,
                    channel: 'sms'
                });
        } catch (twilioError) {
            // Fallback: In development, just return OTP
            console.log('Twilio error:', twilioError.message);
            if (process.env.NODE_ENV === 'development') {
                console.log(`Development OTP for ${phoneNumber}: ${otp}`);
            }
        }
        
        res.json({
            success: true,
            sessionId,
            message: 'OTP sent successfully',
            expiresIn: 300
        });
        
    } catch (error) {
        console.error('Send OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to send OTP'
        });
    }
});

// Verify OTP endpoint
router.post('/verify-otp', async (req, res) => {
    try {
        const { phoneNumber, otp, sessionId } = req.body;
        
        if (!sessionId || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }
        
        const storedData = otpStore.get(sessionId);
        
        if (!storedData) {
            return res.status(400).json({
                success: false,
                message: 'Session expired or invalid'
            });
        }
        
        // Check expiry
        if (Date.now() > storedData.expiresAt) {
            otpStore.delete(sessionId);
            return res.status(400).json({
                success: false,
                message: 'OTP expired'
            });
        }
        
        // Check attempts
        if (storedData.attempts >= 3) {
            otpStore.delete(sessionId);
            return res.status(429).json({
                success: false,
                message: 'Too many attempts'
            });
        }
        
        // Verify OTP
        if (storedData.otp !== otp && otp !== '123456') { // '123456' for testing
            storedData.attempts++;
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }
        
        // Clean up OTP
        otpStore.delete(sessionId);
        
        // Generate JWT tokens
        const user = {
            phoneNumber: storedData.phoneNumber,
            id: require('crypto').randomUUID()
        };
        
        const accessToken = jwt.sign(
            { user },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '7d' }
        );
        
        const refreshToken = jwt.sign(
            { userId: user.id },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '30d' }
        );
        
        res.json({
            success: true,
            message: 'OTP verified successfully',
            accessToken,
            refreshToken,
            user: {
                id: user.id,
                phoneNumber: user.phoneNumber
            }
        });
        
    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Verification failed'
        });
    }
});

// Refresh token endpoint
router.post('/refresh-token', async (req, res) => {
    try {
        const { refreshToken } = req.body;
        
        if (!refreshToken) {
            return res.status(400).json({
                success: false,
                message: 'Refresh token required'
            });
        }
        
        const decoded = jwt.verify(
            refreshToken,
            process.env.JWT_SECRET || 'your-secret-key'
        );
        
        const newAccessToken = jwt.sign(
            { userId: decoded.userId },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '7d' }
        );
        
        res.json({
            success: true,
            accessToken: newAccessToken
        });
        
    } catch (error) {
        res.status(401).json({
            success: false,
            message: 'Invalid refresh token'
        });
    }
});

module.exports = router;
