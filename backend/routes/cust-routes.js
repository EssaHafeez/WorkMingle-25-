const express = require("express");
const router = express.Router();
const custControllers = require("../controllers/cust-controller");

router.route("/").get(custControllers.home);  // Home route for customers
router.route("/register").post(custControllers.register);  // Customer registration
router.route("/login").post(custControllers.login);  // Customer login

// Add the following routes for OTP and password reset functionalities
router.route("/verify-otp").post(custControllers.verifyOtp); // Route for OTP verification
router.route("/forgot-password").post(custControllers.forgotPassword); // Route for requesting a password reset
router.route("/reset-password/:token").post(custControllers.resetPassword); // Route for resetting the password using a token

module.exports = router;
