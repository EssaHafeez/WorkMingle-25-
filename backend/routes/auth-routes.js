const express = require("express");
const router = express.Router();
const authControllers = require("../controllers/auth-controller");

router.route("/register").post(authControllers.register);
router.route("/verify-otp").post(authControllers.verifyOtp); // New route for OTP verification
router.route("/login").post(authControllers.login);
router.route("/forgot-password").post(authControllers.forgotPassword);
router.route("/reset-password/:token").post(authControllers.resetPassword);

module.exports = router;
