// Loading environment variable
if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

// ****** Importing modules ******
var express = require("express"),
  app = express(),
  flash = require("express-flash"),
  bodyParser = require("body-parser"),
  expressSession = require("express-session"),
  passport = require("passport"),
  LocalStrategy = require("passport-local"),
  passportLocalMongoose = require("passport-local-mongoose"),
  mongoose = require("mongoose"),
  configDB = require("./config/database.js"),
  User = require("./models/user.js"),
  // For resetting password
  nodemailer = require("nodemailer"),
  async = require("async"),
  crypto = require("crypto"),
  port = 3000,
  host = "localhost";

// *** Connecting to MongoDB ***
mongoose
  .connect(configDB.url, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to DB");
  })
  .catch((err) => {
    console.log(`Error:\n${err.message}`);
  });

// ****** Setting up the express app *******
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

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

// *** Setting up the passport ***
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new LocalStrategy({ usernameField: "email" }, User.authenticate())
);

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// *** Setting ejs as template engine ***
app.set("view engine", "ejs");
// ===========================
// ****** ROUTES ******

// *** Home Page Route ***
app.get("/", (req, res) => {
  res.render("home");
});

// *** Secret Page Route ***
app.get("/secret/", isLoggedIn, (req, res) => {
  res.render("secret");
});

// *** SignUp Route ***
app.get("/signup/", (req, res) => {
  res.render("signup", {
    expressFlash: req.flash("error"),
    sessionFlash: res.locals.sessionFlash,
  });
});

function validateEmail(email) {
  var re = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
  if (re.test(String(email).toLowerCase())) {
    return true;
  }
  return false;
}

app.post("/signup/", (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;
  var confirm_password = req.body.confirm_password;

  if (password !== confirm_password) {
    req.session.sessionFlash = {
      type: "error",
      message: "Password and Confim Password must be same",
    };
    return res.redirect("/signup/");
  }

  if (!validateEmail(email)) {
    req.session.sessionFlash = {
      type: "error",
      message: "Enter a valid email address",
    };
    return res.redirect("/signup/");
  }

  var userData = {
    username: username,
    email: email,
  };
  User.register(new User(userData), password, (err, user) => {
    if (err) {
      console.log(`Error in Adding the user:\n${err}`);

      if (
        String(err) ===
        "UserExistsError: A user with the given username is already registered"
      ) {
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

// *** LogIn Route ***
app.get("/login/", (req, res) => {
  res.render("login");
});

app.post("/login", function (req, res, next) {
  passport.authenticate("local", function (err, user, info) {
    if (err) {
      return next(err);
    }

    var email = req.body.email;
    var password = req.body.password;
    var confirm_password = req.body.confirm_password;

    if (password !== confirm_password) {
      req.session.sessionFlash = {
        type: "error",
        message: "Password and Confim Password must be same",
      };
      return res.redirect("/login/");
    }

    if (!validateEmail(email)) {
      req.session.sessionFlash = {
        type: "error",
        message: "Enter a valid email address",
      };
      return res.redirect("/login/");
    }

    if (
      String(info) ===
      "IncorrectPasswordError: Password or username is incorrect"
    ) {
      req.session.sessionFlash = {
        type: "error",
        message: "Incorrect Password",
      };
      return res.redirect("/login/");
    }

    if (
      String(info) ===
      "IncorrectUsernameError: Password or username is incorrect"
    ) {
      req.session.sessionFlash = {
        type: "error",
        message: "There is no account with this email address",
      };
      return res.redirect("/login/");
    }

    req.logIn(user, function (err) {
      if (err) {
        return next(err);
      }
      return res.redirect("/secret/");
    });
  })(req, res, next);
});

// *** LogOut Route ***
app.get("/logout/", (req, res) => {
  req.logout();
  res.redirect("/");
});

// *** ResetPassword Route ***
app.get("/reset-password/", (req, res) => {
  res.render("reset-password", { expressFlash: req.flash("success") });
});

app.post("/reset-password/", (req, res, next) => {
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
    (err) => {
      res.redirect("/");
    }
  );
});

// ===========================
// ****** Middelwares ******

// Middleware for Secret Page
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login/");
}

// ****** Are you listening ******
app.listen(port, host, () => {
  console.log(`Server has started on http://${host}:${port}/`);
});
