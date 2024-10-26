const mongoose = require('mongoose');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const otpGenerator = require('otp-generator'); // Add otp-generator

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
  otp: { type: String }, // Add otp field
  otpExpires: { type: Date }, // Add otp expiration field
});

// Middleware for hashing the password before saving
userSchema.pre("save", async function (next) {
  const user = this;
  console.log("actual data", this);

  // Check if password field is modified, if not, move to the next middleware
  if (!user.isModified("password")) {
    return next();
  }

  try {
    const saltRound = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(user.password, saltRound);
    user.password = hashedPassword;
    next(); // Call next to proceed with saving
  } catch (error) {
    return next(error); // Pass error to the next middleware
  }
});

// Method to generate JWT token
userSchema.methods.generateToken = async function () {
  try {
    return jwt.sign(
      {
        userId: this._id.toString(),
        email: this.email,
      },
      process.env.JWT_SECRET_KEY, // Ensure you have this key in your environment variables
      {
        expiresIn: "30d",
      }
    );
  } catch (error) {
    console.error("Token Error:", error);
  }
};

// Compare password method
userSchema.methods.comparePassword = async function (password) {
  return bcrypt.compare(password, this.password);
};

// Method to generate OTP
userSchema.methods.generateOTP = function () {
  const otp = otpGenerator.generate(6, { upperCaseAlphabets: false, specialChars: false });

  // Set the OTP and expiration time (e.g., 10 minutes)
  this.otp = otp;
  this.otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes from now

  return otp; // Return the generated OTP
};

// Verify OTP method
userSchema.methods.verifyOTP = function (inputOtp) {
  // Check if the OTP matches and is not expired
  return this.otp === inputOtp && Date.now() < this.otpExpires;
};

// Method to generate password reset token
userSchema.methods.generatePasswordReset = function () {
  const resetToken = crypto.randomBytes(20).toString('hex');

  // Set resetPasswordToken and expiration (1 hour from now)
  this.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.resetPasswordExpires = Date.now() + 3600000; // 1 hour

  return resetToken;
};

// Create and export the User model
const User = mongoose.model('USER', userSchema);

module.exports = User;
