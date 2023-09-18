const express = require('express');
const authController = require('../controllers/authController'); // Require the controller
const router = express.Router();

// Import middleware modules
const jwtMiddleware = require('../middleware/jwtMiddleware');

// Registration route
router.post('/register', authController.register);

// Send OTP route with rate limiting applied
router.post('/sendotp',  authController.sendOTP);

// Login route
router.post('/alumni/login', authController.alumniLogin);
router.post('/university/login', authController.universityLogin);
router.post('/systemAdmin/login', authController.systemAdminLogin);

// Route to get user wallet and balance with JWT middleware applied
router.get('/getUserWalletAndBalance', jwtMiddleware, authController.getUserWalletAndBalance);

// Route to sign trx with trxData and password
router.post('/signTransaction', jwtMiddleware, authController.signTransaction);


// Other authentication routes can remain the same or be added as needed

module.exports = router;
