const { z } = require("zod");
const Customer = require("../models/cust-model");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");

// Home logic
const home = async (req, res) => {
  try {
    console.log("Home endpoint accessed.");
    res.status(200).json({ msg: "Welcome to our home page" });
  } catch (error) {
    console.error("Error in home:", error);
    res.status(500).json({ msg: "Internal Server Error" });
  }
};

// Send OTP via email
const sendOtpEmail = async (email, otp) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: "OTP for Account Verification",
      text: `Your OTP for account verification is: ${otp}`,
    };

    await transporter.sendMail(mailOptions);
    console.log(`OTP sent to ${email}`);
  } catch (error) {
    console.error("Error sending OTP email:", error);
  }
};

// Zod schema for registration validation
const registerSchema = z.object({
  username: z.string().min(3, "Username must be at least 3 characters long"),
  email: z.string().email("Invalid email address"),
  password: z.string().min(6, "Password must be at least 6 characters long"),
});

// Customer Registration Logic
const register = async (req, res) => {
  try {
    // Validate request body using Zod
    const validatedData = registerSchema.safeParse(req.body);

    if (!validatedData.success) {
      console.log("Validation errors:", validatedData.error.errors);
      return res.status(400).json({ errors: validatedData.error.errors });
    }

    const { username, email, password } = validatedData.data;
    console.log("Registering new customer:", { username, email });

    // Check if the customer with the same email already exists
    const customerExist = await Customer.findOne({ email });

    if (customerExist) {
      console.log("Email already exists:", email);
      return res.status(400).json({ msg: "Email already exists" });
    }

    // Generate OTP for verification
    const otp = otpGenerator.generate(6, { digits: true, alphabets: false, upperCase: false, specialChars: false });
    console.log("Generated OTP:", otp);

    // Create new customer
    const customerCreated = await Customer.create({ username, email, password, otp });
    console.log("Customer created successfully:", customerCreated);

    // Send OTP via email
    await sendOtpEmail(email, otp);

    res.status(201).json({
      msg: "Registration Successful. OTP sent to your email.",
      customerId: customerCreated._id.toString(),
      username: customerCreated.username,
      email: customerCreated.email,
    });
  } catch (error) {
    console.error("Error during customer registration:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Zod schema for login validation
const loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(6, "Password must be at least 6 characters long"),
});

// Customer Login Logic
const login = async (req, res) => {
  try {
    // Validate request body using Zod
    const validatedData = loginSchema.safeParse(req.body);

    if (!validatedData.success) {
      console.log("Validation errors:", validatedData.error.errors);
      return res.status(400).json({ errors: validatedData.error.errors });
    }

    const { email, password } = validatedData.data;
    console.log("Logging in customer:", { email });

    const customerExist = await Customer.findOne({ email });

    if (!customerExist) {
      console.log("Customer not found:", email);
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Validate password
    const isPasswordValid = await customerExist.comparePassword(password);

    if (isPasswordValid) {
      console.log("Login successful for:", customerExist.username);
      res.status(200).json({
        message: "Login Successful",
        token: await customerExist.generateToken(),
        customerId: customerExist._id.toString(),
      });
    } else {
      console.log("Invalid password for:", email);
      res.status(401).json({ message: "Invalid email or password" });
    }
  } catch (error) {
    console.error("Error during customer login:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Verify OTP
const verifyOtp = async (req, res) => {
  const { email, otp } = req.body;
  console.log("Verifying OTP for:", { email, otp });

  try {
    const customer = await Customer.findOne({ email });

    if (!customer) {
      console.log("Customer not found:", email);
      return res.status(400).json({ message: "Customer not found" });
    }

    // Check if the OTP matches
    if (customer.otp !== otp) {
      console.log("Invalid OTP:", otp);
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // Clear OTP after verification
    customer.otp = null; // Clear OTP after successful verification
    await customer.save();
    console.log("OTP verified successfully for:", email);

    // Generate token and send response
    res.status(200).json({
      msg: "OTP verified successfully",
      token: await customer.generateToken(),
      customerId: customer._id.toString(),
    });
  } catch (error) {
    console.error("Error verifying OTP:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Forgot Password logic
const forgotPassword = async (req, res) => {
  const { email } = req.body;
  console.log("Forgot password request for:", email);
  
  try {
    const customer = await Customer.findOne({ email });
    if (!customer) {
      console.log("Customer not registered:", email);
      return res.json({ message: "Customer not registered" });
    }

    const token = jwt.sign({ id: customer._id }, process.env.JWT_SECRET_KEY, {
      expiresIn: "5m",
    });

    const encodedToken = encodeURIComponent(token).replace(/\./g, "%2E");
    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: "Reset Password",
      text: `http://localhost:3000/resetPassword/${encodedToken}`,
    };

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
      },
    });

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.error("Nodemailer Error: ", error);
        return res.json({ message: "Error sending email" });
      } else {
        console.log("Password reset email sent to:", email);
        return res.json({ status: true, message: "Email sent" });
      }
    });
  } catch (err) {
    console.error("Error in forgotPassword:", err);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Reset Password logic
const resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  console.log("Resetting password with token:", token);

  try {
    const decoded = await jwt.verify(token, process.env.JWT_SECRET_KEY);
    const id = decoded.id;
    const hashPassword = await bcrypt.hash(password, 10);
    await Customer.findByIdAndUpdate({ _id: id }, { password: hashPassword });
    console.log("Password updated successfully for ID:", id);
    return res.json({ status: true, message: "Password updated successfully" });
  } catch (err) {
    console.error("Error resetting password:", err);
    return res.json({ message: "Invalid or expired token" });
  }
};

// Export the updated controller for Customer
module.exports = {
  home,
  register,
  verifyOtp,
  login,
  forgotPassword,
  resetPassword,
};
