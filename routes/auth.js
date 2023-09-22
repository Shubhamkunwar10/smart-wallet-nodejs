const express = require('express');
const authController = require('../controllers/authController'); // Require the controller
const router = express.Router();

// Import middleware modules
const jwtMiddleware = require('../middleware/jwtMiddleware');

// Registration route
router.post('/user/signup', authController.register);
router.post('/alumni/login', authController.alumniLogin);

// Login route
router.post('/university/login', authController.universityLogin);
router.post('/systemAdmin/login', authController.systemAdminLogin);

// Route to sign trx with trxData and password
router.post('/signTransaction', jwtMiddleware, authController.signTransaction);

// Login route
router.post('/alumni/logout', authController.alumniLogout);
router.post('/university/logout', authController.universityLogout);
router.post('/systemAdmin/logout', authController.systemAdminLogout);


// Route to get user wallet and balance with JWT middleware applied
router.get('/getUserWalletAndBalance', jwtMiddleware, authController.getUserWalletAndBalance);

router.get('/alumni/getProfile',jwtMiddleware,  authController.getProfile);



module.exports = router;
