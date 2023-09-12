const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { encrypt, decrypt,generateWallet, getWalletBalance, signTransaction  } = require('../utils/crypto');
const { generateOTP, verifyOTP } = require('../utils/otp');
const bcrypt = require('bcrypt');

const authenticationController = {
  // Register a new user
  register: async (req, res) => {
    try {
      const { email, password } = req.body;

      // Check if the email is already registered
      const existingUser = await User.findByEmail(email);
      if (existingUser) {
        return res.status(400).json({ error: 'Email is already registered' });
      }

      // Generate a new Ethereum wallet using Web3.js
      const wallet = await generateWallet();

      // Encrypt the private key before saving it
      const encryptedPrivateKey = encrypt(wallet.privateKey, password);

      // Generate and send OTP (You can use your preferred method to send OTP)
      const otp = "123456" // Implement a function to generate OTP
      // Send the OTP to the user's email or via another preferred method

      // Store the OTP hash in the user document (for verification during login)
      const otpHash = bcrypt.hashSync(otp, 10);

      // Hash the user's password before storing it in the database
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create a new user with the email, hashed password, wallet details, and OTP hash
      const user = new User({
        email,
        password: hashedPassword,
        walletAddress: wallet.address,
        encryptedPrivateKey,
        otpHash,
      });

      await user.save();
      res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Registration failed' });
    }
  },

  // Send OTP to the user's email
  sendOTP: async (req, res) => {
    try {
      const { email } = req.body;

      const user = await User.findByEmail(email);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Generate and send OTP (You can use your preferred method to send OTP)
      const otp = generateOTP(); // Implement a function to generate OTP
      // Send the OTP to the user's email or via another preferred method
      console.log(otp)

      // Store the OTP hash in the user document (for verification during login)
      user.otpHash = bcrypt.hashSync(otp, 10);
      await user.save();

      res.json({ message: `OTP sent successfully: ${otp}` });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to send OTP' });
    }
  },

  // Login with email and OTP
  // Login with email and OTP, and return a JWT
  login: async (req, res) => {
    try {
      const { email, otp } = req.body;
  
      const user = await User.findByEmail(email);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      // Verify OTP
      const isOTPValid = verifyOTP(otp, user.otpHash);
      if (!isOTPValid) {
        return res.status(401).json({ error: 'Invalid OTP' });
      }
  
      // OTP is valid, generate JWT token for authentication
      const token = jwt.sign({ sub: user._id, email: user.email }, process.env.SECRET_KEY, { expiresIn: '10h' });
  
      // Send the JWT token in the response
      res.json({ message: 'Login successful', token });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Login failed' });
    }
  },
  

// Sign a transaction using the user's password and private key
signTransaction: async (req, res) => {
  try {
    const { password, encodedABIData, nonce } = req.body;

    // Verify the JWT token and retrieve the user's ID
    const {email } = req.user; // Use req.user instead of localStorage

    // Find the user by ID
    const user = await User.findByEmail(email);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Decrypt the user's private key using the password
    const privateKey = decrypt(user.encryptedPrivateKey, password);

    // Sign the transaction using the decrypted private key
    const signedTransaction = await signTransaction( encodedABIData, nonce, privateKey);

    res.json({ message: 'Transaction signed successfully', signedTransaction });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Transaction signing failed' });
  }
},

  getUserWalletAndBalance: async (req, res) => {
    try {
      const { email } = req.user; // Retrieve user's email from the authenticated JWT

      // Find the user by email
      const user = await User.findByEmail(email);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Get the user's wallet address from the user document
      const walletAddress = user.walletAddress;

      // Get the balance of the user's wallet
      const balance = await getWalletBalance(walletAddress);

      res.json({ walletAddress, balance });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to get user wallet and balance' });
    }
  }

  
  
};

module.exports = authenticationController;
