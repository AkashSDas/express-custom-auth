const mongoose = require("mongoose"),
  passportLocalMongoose = require("passport-local-mongoose");

/**
 * User schema
 */
const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },

  resetPasswordToken: String,
  resetPasswordExpires: Date,
});

// Changing the username field from username to email,
// that will be the identity of an individual user
UserSchema.plugin(passportLocalMongoose, {
  usernameField: "email",
});

// Exporting the compilied model
module.exports = mongoose.model("User", UserSchema);
