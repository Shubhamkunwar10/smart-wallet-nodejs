const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const passport = require('passport');

dotenv.config();
const rateLimiter = require('./middleware/rateLimiter'); // Require rate limiting middleware
const { connectToDatabase } = require('./config/db'); // Import the database connection function



const app = express();
const port = process.env.PORT || 80003;

app.use(bodyParser.json());
app.use(cors());

// Connect to MongoDB
connectToDatabase();


// Initialize Passport middleware
app.use(passport.initialize());

// Apply rate limiting middleware globally or as needed
app.use('/auth/sendotp', rateLimiter);
// Apply rate limiting middleware to specific routes
app.use('/auth/login', rateLimiter);

// Use the authentication routes
app.use('/auth', require('./routes/auth'));

// Other routes can be added as needed

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
