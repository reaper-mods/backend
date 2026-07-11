const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access token required'
        });
    }
    
    jwt.verify(
        token,
        process.env.JWT_SECRET || 'your-secret-key',
        (err, decoded) => {
            if (err) {
                return res.status(403).json({
                    success: false,
                    message: 'Invalid or expired token'
                });
            }
            req.user = decoded.user || decoded;
            next();
        }
    );
};

// Get user's chats
router.get('/', authenticateToken, async (req, res) => {
    try {
        // In production, fetch from database
        const chats = [
            {
                id: '1',
                name: 'John Doe',
                lastMessage: 'Hey, how are you?',
                timestamp: new Date().toISOString(),
                unreadCount: 2,
                avatar: null,
                isOnline: true
            },
            {
                id: '2',
                name: 'Jane Smith',
                lastMessage: 'See you tomorrow!',
                timestamp: new Date(Date.now() - 3600000).toISOString(),
                unreadCount: 0,
                avatar: null,
                isOnline: false
            }
        ];
        
        res.json({
            success: true,
            chats
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to fetch chats'
        });
    }
});

// Get chat messages
router.get('/:chatId/messages', authenticateToken, async (req, res) => {
    try {
        const { chatId } = req.params;
        
        // In production, fetch from database
        const messages = [
            {
                id: '1',
                chatId,
                senderId: req.user.id,
                content: 'Hello!',
                timestamp: new Date(Date.now() - 7200000).toISOString(),
                status: 'read'
            },
            {
                id: '2',
                chatId,
                senderId: 'other-user',
                content: 'Hi there!',
                timestamp: new Date(Date.now() - 3600000).toISOString(),
                status: 'delivered'
            }
        ];
        
        res.json({
            success: true,
            messages
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to fetch messages'
        });
    }
});

module.exports = router;