require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet"); // Import Helmet for basic security
const rateLimit = require("express-rate-limit"); // Import rate limiter
const connectDb = require("./connection/db"); // Single connection for database
const authRoutes = require("./routes/auth-routes"); // Authentication routes
const custRouter = require("./routes/cust-routes"); // Customer routes

const app = express();

// Middleware to enhance security using HTTP headers
app.use(helmet());

// Middleware to enable CORS for all requests
app.use(cors());

// Middleware to parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate Limiting Middleware to prevent brute-force attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later.",
});
app.use("/api/", limiter); // Apply rate limiting to API routes

// Mount the Routers at specific URL prefixes
app.use("/api/auth", authRoutes); // Auth routes
app.use("/api/cust", custRouter); // Customer routes

const PORT = process.env.PORT || 5000;

// Check if required environment variables are set
if (!process.env.JWT_SECRET_KEY) {
  console.error("JWT_SECRET_KEY environment variable is not set.");
  process.exit(1); // Exit the process if the variable is not set
}

// Connect to the database and start the server
connectDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server is running at http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Database connection failed:', error.message);
  });
