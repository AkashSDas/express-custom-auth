/**
 * Loading environment variables
 */
if (process.env.NODE_ENV !== "production") require("dotenv").config();

/**
 * Importing packages
 */
const express = require("express"),
  app = express(),
  flash = require("express-flash"),
  expressSession = require("express-session"),
  passport = require("passport"),
  LocalStrategy = require("passport-local"),
  mongoose = require("mongoose"),
  User = require("./models/user.js"),
  // For resetting password
  nodemailer = require("nodemailer"),
  async = require("async"),
  crypto = require("crypto"),
  port = 3000,
  host = "localhost";

/**
 * Connecting to MongoDB
 */
mongoose
  .connect(process.env.MONGODB_URL, {
    useCreateIndex: true,
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.log(`Error: \n${err.message}`));

/**
 * Setting up all the middlewares
 */
app.use(express.static("public"));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  expressSession({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(flash());

// Custom flash middleware -- from Ethan Brown's book, 'Web Development with Node & Express'
app.use((req, res, next) => {
  // if there's a flash message in the session request, make it available in the response, then delete it
  res.locals.sessionFlash = req.session.sessionFlash;
  delete req.session.sessionFlash;
  next();
});

app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new LocalStrategy({ usernameField: "email" }, User.authenticate())
);
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// Setting EJS as our template engine
// so that we don't need to add .ejs in `<template name>.ejs`
app.set("view engine", "ejs");

/**
 * ==================
 * ROUTES
 * ==================
 */

/**
 * home/index route
 */
app.get("/", (req, res) => {
  res.render("home");
});

/**
 * secret route
 */
app.get("/secret/", isLoggedIn, (req, res) => {
  res.render("secret");
});

/**
 * SignUp GET route
 */
app.get("/signup/", (req, res) => {
  res.render("signup", {
    expressFlash: req.flash("error"),
    sessionFlash: res.locals.sessionFlash,
  });
});

/**
 * SignUp POST route
 */
app.post("/signup/", (req, res) => {
  const { username, email, password, confirm_password } = req.body;

  // Check password
  if (password !== confirm_password) {
    req.session.sessionFlash = {
      type: "error",
      message: "Password and Confim Password must be same",
    };
    return res.redirect("/signup/");
  }

  // Check email
  if (!validateEmail(email)) {
    req.session.sessionFlash = {
      type: "error",
      message: "Enter a valid email address",
    };
    return res.redirect("/signup/");
  }

  // Add user
  const userData = { username, email };
  User.register(new User(userData), password, (err, user) => {
    if (err) {
      console.log(`Error in Adding the user:\n${err}`);

      const emailTakenErr =
        "UserExistsError: A user with the given username is already registered";

      if (String(err) === emailTakenErr) {
        req.session.sessionFlash = {
          type: "error",
          message: "This email address is taken, Try some other email address",
        };
        return res.redirect("/signup/");
      }
    } else {
      res.redirect("/login/");
    }
  });
});

/**
 * Login GET route
 */
app.get("/login/", (req, res) => {
  res.render("login");
});

/**
 * Login POST route
 */
app.post("/login/", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    const { email, password, confirm_password } = req.body;

    // Check password
    if (password !== confirm_password) {
      req.session.sessionFlash = {
        type: "error",
        message: "Password and Confim Password must be same",
      };
      return res.redirect("/login/");
    }

    // Validate email
    if (!validateEmail(email)) {
      req.session.sessionFlash = {
        type: "error",
        message: "Enter a valid email address",
      };
      return res.redirect("/login/");
    }

    const incorretPwdErr =
      "IncorrectPasswordError: Password or username is incorrect";
    if (String(info) === incorretPwdErr) {
      req.session.sessionFlash = {
        type: "error",
        message: "Incorrect Password",
      };
      return res.redirect("/login/");
    }

    const incorrectEmail =
      "IncorrectUsernameError: Password or username is incorrect";
    if (String(info) === incorrectEmail) {
      req.session.sessionFlash = {
        type: "error",
        message: "There is no account with this email address",
      };
      return res.redirect("/login/");
    }

    req.logIn(user, function (err) {
      if (err) return next(err);
      return res.redirect("/secret/");
    });
  })(req, res, next);
});

/**
 * Logout route
 */
app.get("/logout/", (req, res) => {
  req.logout();
  res.redirect("/");
});

/**
 * Password reset GET route
 */
app.get("/reset-password/", (req, res) => {
  res.render("reset-password", { expressFlash: req.flash("success") });
});

/**
 * Password reset POST route
 */
app.post("/reset-password/", (req, res) => {
  async.waterfall(
    [
      // 1.
      (done) => {
        crypto.randomBytes(20, (err, buffer) => {
          var token = buffer.toString("hex");
          done(err, token);
        });
      },

      // 2.
      (token, done) => {
        User.findOne({ email: req.body.email }, (err, user) => {
          if (!user) {
            req.session.sessionFlash = {
              type: "error",
              message: "No account with that email address exists",
            };
            return res.redirect("/reset-password/");
          }

          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

          user.save((err) => {
            done(err, token, user);
          });
        });
      },

      // 3.
      (token, user, done) => {
        var smtpTransport = nodemailer.createTransport({
          service: "Gmail",
          auth: {
            user: process.env.GMAIL_ADDRESS,
            pass: process.env.GMAILPSWD,
          },
        });

        var mailOptions = {
          to: user.email,
          from: process.env.GMAIL_ADDRESS,
          subject: "Password Reset",
          text: `You are receiving this because you (or someone else) have requested the reset of the password. Please click on the following link, or paste this into your browser to complete the process of password reset, link -> http://${req.headers.host}/reset/${token} \n\n If you did not request this, please ignore this email and your password will remain unchanged.`,
        };

        smtpTransport.sendMail(mailOptions, (err) => {
          console.log("Mail Sent");
          req.flash(
            "success",
            `An email has been sent to ${user.email} with futher instructions`
          );
          done(err, "done");
        });
      },
    ],
    (err) => {
      if (err) {
        return next(err);
      }
      res.redirect("/reset-password/");
    }
  );
});

/**
 * Reset password token GET route
 */
app.get("/reset/:token/", (req, res) => {
  User.findOne(
    {
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() },
    },
    (err, user) => {
      if (!user) {
        req.session.sessionFlash = {
          type: "error",
          message: "Password reset token is invalid or has expired",
        };
        return res.redirect("/reset-password/");
      }

      res.render("reset", { token: req.params.token });
    }
  );
});

/**
 * Reset password token POST route
 */
app.post("/reset/:token/", (req, res) => {
  async.waterfall(
    [
      // 1.
      (done) => {
        User.findOne(
          {
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() },
          },
          (err, user) => {
            if (req.body.password === req.body.confirm_password) {
              user.setPassword(req.body.password, (err) => {
                user.resetPasswordToken = undefined;
                user.resetPasswordExpires = undefined;

                user.save((err) => {
                  res.redirect("/login/");
                  done(err, user);
                });
              });
            } else {
              req.session.sessionFlash = {
                type: "error",
                message: "Password and Confirm Password must match",
              };
              return res.redirect("back");
            }
          }
        );
      },

      // 2.
      (user, done) => {
        var smtpTransport = nodemailer.createTransport({
          service: "Gmail",
          auth: {
            user: process.env.GMAIL_ADDRESS,
            pass: process.env.GMAILPSWD,
          },
        });

        var mailOptions = {
          to: user.email,
          from: process.env.GMAIL_ADDRESS,
          subject: "Password is successfully reset",
          text: `This is a confirmation that the password for your account ${user.email} with username ${user.username} has successfully reset`,
        };

        smtpTransport.sendMail(mailOptions, (err) => {
          console.log("Mail Sent");
          req.flash("success", `Your password has been changed`);
          done(err, "done");
        });
      },
    ],
    (err) => res.redirect("/")
  );
});

/**
 * Middleware for secret page
 */
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login/");
}

/**
 * Validate email
 */
function validateEmail(email) {
  var re = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
  if (re.test(String(email).toLowerCase())) return true;
  return false;
}

/**
 * Start the express
 */
app.listen(port, host, () => {
  console.log(`Server has started on http://${host}:${port}/`);
});
