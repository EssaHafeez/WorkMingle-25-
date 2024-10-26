const mongoose = require("mongoose");

// Access the environment variable properly
const URI = process.env.MONGODB_URI;

const connectDb = async () => {
  try {
    await mongoose.connect(URI); // No need for the deprecated options
    console.log("Connection successful to DB");
  } catch (error) {
    console.error("Database connection failed:", error.message);
    process.exit(1);
  }
};

module.exports = connectDb;
