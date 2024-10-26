const User = require("../models/user-model");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const crypto = require("crypto"); // Import crypto for OTP
const otpGenerator = require("otp-generator");
const { z } = require("zod"); // Import Zod

// Define Zod schema for registration
const registrationSchema = z.object({
  username: z.string().min(3, { message: "Username must be at least 3 characters long" }),
  email: z.string().email({ message: "Invalid email address" }),
  password: z.string().min(6, { message: "Password must be at least 6 characters long" }),
});

// Define Zod schema for login
const loginSchema = z.object({
  email: z.string().email({ message: "Invalid email address" }),
  password: z.string().min(6, { message: "Password must be at least 6 characters long" }),
});

// Home logic
const home = async (req, res) => {
  try {
    res.status(200).json({ msg: "Welcome to our home page" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ msg: "Internal Server Error" });
  }
};

// User Registration Logic 📝
// 1. Get Registration Data: 📤 Retrieve user data (username, email, password).
// 2. Check Email Existence: 📋 Check if the email is already registered.
// 3. Hash Password: 🔒 Securely hash the password (done in the model).
// 4. Create User: 📝 Create a new user with hashed password.
// 5. Save to DB: 💾 Save user data to the database.
// 6. Respond: ✅ Respond with "Registration Successful" or handle errors.

const register = async (req, res) => {
  try {
    // Validate registration data
    const result = registrationSchema.safeParse(req.body);
    if (!result.success) {
      // If validation fails, send error message
      return res.status(400).json({
        message: "Validation Error",
        errors: result.error.errors.map(err => ({ field: err.path[0], message: err.message })),
      });
    }

    const { username, email, password } = result.data;

    // Check if the user with the same email already exists
    const userExist = await User.findOne({ email });

    if (userExist) {
      return res.status(400).json({ msg: "Email already exists" });
    }

    // Generate OTP for verification
    const otp = otpGenerator.generate(6, { digits: true, alphabets: false, upperCase: false, specialChars: false });

    // Create new user
    const userCreated = await User.create({ username, email, password, otp });

    // Send OTP via email (using Nodemailer)
    await sendOtpEmail(email, otp);

    res.status(201).json({
      msg: "Registration Successful. OTP sent to your email.",
      userId: userCreated._id.toString(),
      username: userCreated.username,
      email: userCreated.email,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Function to send OTP via email
const sendOtpEmail = async (email, otp) => {
  try {
    var transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
      },
    });

    var mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: "OTP for Account Verification",
      text: `Your OTP for account verification is: ${otp}`,
    };

    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error("Error sending OTP email:", error);
  }
};

// Verify OTP
const verifyOtp = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    // Check if the OTP matches
    if (user.otp !== otp) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // Clear OTP after verification
    user.otp = null;
    await user.save();

    // Generate token and send response
    res.status(200).json({
      msg: "OTP verified successfully",
      token: await user.generateToken(),
      userId: user._id.toString(),
    });
  } catch (error) {
    console.error("Error verifying OTP:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Login logic
const login = async (req, res) => {
  try {
    // Validate login data
    const result = loginSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        message: "Validation Error",
        errors: result.error.errors.map(err => ({ field: err.path[0], message: err.message })),
      });
    }

    const { email, password } = result.data;

    const userExist = await User.findOne({ email });

    if (!userExist) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isPasswordValid = await userExist.comparePassword(password);

    if (isPasswordValid) {
      res.status(200).json({
        message: "Login Successful",
        token: await userExist.generateToken(),
        userId: userExist._id.toString(),
      });
    } else {
      res.status(401).json({ message: "Invalid email or password" });
    }
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
};

// Forgot Password logic
const forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ message: "User not registered" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET_KEY, {
      expiresIn: "5m",
    });

    var transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
      },
    });

    const encodedToken = encodeURIComponent(token).replace(/\./g, "%2E");
    var mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: "Reset Password",
      text: `http://localhost:3000/resetPassword/${encodedToken}`,
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.error("Nodemailer Error: ", error);
        return res.json({ message: "Error sending email" });
      } else {
        return res.json({ status: true, message: "Email sent" });
      }
    });
  } catch (err) {
    console.log("Error in forgotPassword:", err);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Reset Password logic
const resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  try {
    const decoded = await jwt.verify(token, process.env.JWT_SECRET_KEY);
    const id = decoded.id;
    const hashPassword = await bcrypt.hash(password, 10);
    await User.findByIdAndUpdate({ _id: id }, { password: hashPassword });
    return res.json({ status: true, message: "Password updated successfully" });
  } catch (err) {
    return res.json({ message: "Invalid or expired token" });
  }
};

module.exports = {
  home,
  register,
  login,
  forgotPassword,
  resetPassword,
  verifyOtp, // Add OTP verification function to exports
};
