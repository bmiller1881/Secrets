//jshint esversion:6

//load JS modules
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("cookie-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

//create the express application
const app = express();

//setup application middleware
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      maxAge: 60000,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

//set variable to URL of environment path
const setDeploymentEnv = "https://secrets-project-bmiller-test.herokuapp.com";

//connect to MongoDB
mongoose.connect(
  "mongodb+srv://bmiller1881:" +
    process.env.CLIENT_SECRET_MONGODB +
    "@cluster0.clksm.mongodb.net/userDB?retryWrites=true&w=majority"
);

//create schhema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: [String],
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//create collection
const User = new mongoose.model("User_test", userSchema);

//setup passport.js to use userDB
passport.use(User.createStrategy());

//serialize and deserialize user session
//explanation:"https://stackoverflow.com/questions/27637609/understanding-passport-serialize-deserialize"
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

//Google strategy setup to enable login with Google Account
//documentation: "https://www.passportjs.org/packages/passport-google-oauth20/"
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: setDeploymentEnv + "/auth/google/secrets",
    },
    //API: "https://console.cloud.google.com/apis/credentials/consent/"
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

//Facebook strategy setup to enable login with Google Account
//documentation: "https://www.passportjs.org/packages/passport-facebook/"
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.CLIENT_ID_FB,
      clientSecret: process.env.CLIENT_SECRET_FB,
      callbackURL: setDeploymentEnv + "/auth/facebook/secrets",
    },
    //API: "https://developers.facebook.com/apps/"
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.route("/").get(function (req, res) {
  res.render("home");
});

//authenticate using google account
app
  .route("/auth/google")
  .get(passport.authenticate("google", { scope: ["email", "profile"] }));

app
  .route("/auth/google/secrets")
  .get(
    passport.authenticate("google", { failureRedirect: "/login" }),
    function (req, res) {
      // Successful authentication, redirect to secrets.
      res.redirect("/secrets");
    }
  );

//authenticate using facebook account
app.route("/auth/facebook").get(passport.authenticate("facebook"));

app
  .route("/auth/facebook/secrets")
  .get(
    passport.authenticate("facebook", { failureRedirect: "/login" }),
    function (req, res) {
      // Successful authentication, redirect to secrets.
      res.redirect("/secrets");
    }
  );

//authenticate using local Passport strategy
app
  .route("/login")
  .get(function (req, res) {
    res.render("login");
  })
  .post(function (req, res) {
    const user = new User({
      username: req.body.username,
      password: req.body.password,
    });
    req.login(user, function (err) {
      if (err) {
        console.log(err);
        res.redirect("/login");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    });
  });

//secrets page can only be accessed when logged in
app.route("/secrets").get(function (req, res) {
  User.find({ secret: { $ne: null } }, function (err, foundUsers) {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", { usersWithSecrets: foundUsers });
      }
    }
  });
});

app
  .route("/submit")
  .get(function (req, res) {
    if (req.isAuthenticated()) {
      res.render("submit");
    } else {
      res.redirect("/login");
    }
  })
  .post(function (req, res) {
    // const submittedSecret = submittedSecret.push(req.body.secret);
    console.log(req.user.id);
    User.findById(req.user.id, function (err, foundUser) {
      if (err) {
        console.log(err);
      } else {
        if (foundUser) {
          foundUser.secret.push(req.body.secret);
          foundUser.save(function () {
            res.redirect("/secrets");
          });
        }
      }
    });
  });

app
  .route("/register")
  .get(function (req, res) {
    res.render("register");
  })
  .post(function (req, res) {
    User.register(
      { username: req.body.username },
      req.body.password,
      function (err, user) {
        if (err) {
          console.log(err);
          res.redirect("/register");
        } else {
          passport.authenticate("local")(req, res, function () {
            res.redirect("/secrets");
          });
        }
      }
    );
  });

app.route("/logout").get(function (req, res) {
  req.logout();
  res.redirect("/");
});

app.listen(process.env.PORT || 3000, function () {
  console.log("Server started.");
});
