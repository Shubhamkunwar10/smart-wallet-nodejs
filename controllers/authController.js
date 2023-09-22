const jwt = require("jsonwebtoken");
const User = require("../models/User");
const {
  encrypt,
  decrypt,
  generateWallet,
  getWalletBalance,
  signTransaction,
} = require("../utils/crypto");
const { generateOTP, verifyOTP } = require("../utils/otp");
const bcrypt = require("bcrypt");

const authenticationController = {
  register: async (req, res) => {
    try {
      const { email, password, phoneNumber, category } = req.body;

      // Check if the email is already registered
      const existingUser = await User.findByEmail(email);

      if (existingUser) {
        return res.status(400).json({ error: "User Already Exists." });
      }

      // Generate a new Ethereum wallet using Web3.js
      const wallet = await generateWallet();

      // Encrypt the private key before saving it
      const encryptedPrivateKey = encrypt(wallet.privateKey, password);

      // Create a new user with the email, hashed password, wallet details, and user type
      const user = new User({
        email,
        password: password,
        walletAddress: wallet.address,
        encryptedPrivateKey,
        phoneNumber,
        category, 
      });

      await user.save();
      res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Registration failed" });
    }
  },

  // Login with email and password, and return a JWT
  alumniLogin: async (req, res) => {
    try {
      const { email, password } = req.body;

      const user = await User.findByEmail(email);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Verify the password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ error: "Invalid password" });
      }

      // Check if category is "student" or "alumni"
      if (user.category !== "student" && user.category !== "alumni") { // Use && instead of ||
        return res
          .status(403)
          .json({ error: "Do not have enough Permission " });
      }
      const balance = await getWalletBalance(user.walletAddress);

      // Generate JWT token for authentication
      const token = jwt.sign(
        {
          sub: user._id,
          email: user.email,
          walletAddress: user.walletAddress,
          category: user.category,
          walletBalance:balance
        },
        process.env.SECRET_KEY,
        { expiresIn: "10h" }
      );

      // Send the JWT token in the response
      res.json({ message: "Login successful", token });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Login failed" });
    }
  },

  // University Login
  universityLogin: async (req, res) => {
    try {
      const { email, password } = req.body;

      const user = await User.findByEmail(email);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Verify the password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ error: "Invalid password" });
      }

      // Check if category is "university"
      if (user.category !== "admin") {
        return res
          .status(403)
          .json({ error: "Do not have enough Permission " });
      }

      const balance = await getWalletBalance(user.walletAddress);

      // University login is valid, generate JWT token for authentication
      const token = jwt.sign(
        {
          sub: user._id,
          email: user.email,
          walletAddress: user.walletAddress,
          category: user.category,
          walletBalance:balance
        },
        process.env.SECRET_KEY,
        { expiresIn: "10h" }
      );

      // Send the JWT token in the response
      res.json({ message: "University login successful", token });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "University login failed" });
    }
  },

  // System Admin Login
  systemAdminLogin: async (req, res) => {
    try {
      const { email, password } = req.body;

      const user = await User.findByEmail(email);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Verify the password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ error: "Invalid password" });
      }

      // Check if category is "systemadmin"
      if (user.category !== "systemadmin") {
        return res
          .status(403)
          .json({ error: "Do not have enough Permission " });
      }
      const balance = await getWalletBalance(user.walletAddress);


      // System Admin login is valid, generate JWT token for authentication
      const token = jwt.sign(
        {
          sub: user._id,
          email: user.email,
          walletAddress: user.walletAddress,
          category: user.category,
          walletBalance:balance
        },
        process.env.SECRET_KEY,
        { expiresIn: "10h" }
      );

      // Send the JWT token in the response
      res.json({ message: "System Admin login successful", token });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "System Admin login failed" });
    }
  },

  
  // Sign a transaction using the user's password and private key
  signTransaction: async (req, res) => {
    try {
      const { password, encodedABIData, nonce } = req.body;

      // Verify the JWT token and retrieve the user's ID
      const { email } = req.user; // Use req.user instead of localStorage

      // Find the user by ID
      const user = await User.findByEmail(email);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Decrypt the user's private key using the password
      const privateKey = decrypt(user.encryptedPrivateKey, password);

      // Sign the transaction using the decrypted private key
      const signedTransaction = await signTransaction(
        encodedABIData,
        nonce,
        privateKey
      );

      res.json({
        message: "Transaction signed successfully",
        signedTransaction,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Transaction signing failed" });
    }
  },

  getUserWalletAndBalance: async (req, res) => {
    console.log(req.user);
    try {
      const { email } = req.user; // Retrieve user's email from the authenticated JWT
      // Find the user by email
      const user = await User.findByEmail(email);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Get the user's wallet address from the user document
      const walletAddress = user.walletAddress;

      // Get the balance of the user's wallet
      const balance = await getWalletBalance(walletAddress);

      res.json({ walletAddress, balance });
    } catch (err) {
      console.error(err);
      console.log(req.user);

      res.status(500).json({ error: "Failed to get user wallet and balance" });
    }
  },
  // Alumni Profile Route
  getProfile: async (req, res) => {
    try {
      const { email } = req.user; // Get the user's category from the JWT
      console.log(email);

      // Find the user by email
      const user = await User.findByEmail(email);

      res.json({
        user,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to get alumni profile" });
    }
  },

  // Alumni Logout
  alumniLogout: async (req, res) => {
    try {
      // Assuming the client sends the token in the request headers
      const bearerToken = req.headers.authorization;

      if (!bearerToken || !bearerToken.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      // Extract the JWT token (remove 'Bearer ' from the token string)
      const token = bearerToken.split(" ")[1];

      // Invalidate the token by setting its expiry time to an earlier time (e.g., 1 second ago)
      // You can also add it to a list of invalidated tokens if needed

      // Respond with a logout message
      res.json({ message: "University logout successful" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "University logout failed" });
    }
  },

  // University Logout
  universityLogout: async (req, res) => {
    try {
      // Assuming the client sends the token in the request headers
      const bearerToken = req.headers.authorization;

      if (!bearerToken || !bearerToken.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      // Extract the JWT token (remove 'Bearer ' from the token string)
      const token = bearerToken.split(" ")[1];

      // Invalidate the token by setting its expiry time to an earlier time (e.g., 1 second ago)
      // You can also add it to a list of invalidated tokens if needed

      // Respond with a logout message
      res.json({ message: "University logout successful" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "University logout failed" });
    }
  },

  // SystemAdmin Logout
  systemAdminLogout: async (req, res) => {
    try {
      // Assuming the client sends the token in the request headers
      const bearerToken = req.headers.authorization;

      if (!bearerToken || !bearerToken.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      // Extract the JWT token (remove 'Bearer ' from the token string)
      const token = bearerToken.split(" ")[1];

      // Invalidate the token by setting its expiry time to an earlier time (e.g., 1 second ago)
      // You can also add it to a list of invalidated tokens if needed

      // Respond with a logout message
      res.json({ message: "University logout successful" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "University logout failed" });
    }
  },

};

module.exports = authenticationController;
