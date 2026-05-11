// Load environment variables from .env file
require("dotenv").config();

// Import necessary modules
const express = require("express");
const session = require("express-session");
const MongoDBStore = require("connect-mongodb-session")(session);
const bcrypt = require("bcrypt");
const saltRounds = 12;
const Joi = require("joi");

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;
const ExpireTime = 60 * 60 * 1000; // 1 hour

// Set EJS as the templating engine
app.set("view engine", "ejs");

// Import database connection
const { database } = require("./databaseConnection");

// Connect to MongoDB collections
const userCollection = database
  .db(process.env.MONGODB_DATABASE)
  .collection("users");

// Middleware configuration
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from the "public" directory
app.use(express.static(__dirname + "/public"));

// Configure session store with MongoDB
var mongoStore = new MongoDBStore({
  uri: `mongodb+srv://${process.env.MONGODB_USER}:${encodeURIComponent(process.env.MONGODB_PASSWORD)}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`,
  collection: "sessions",
});

// Session configuration
app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    store: mongoStore,
    resave: true,
    saveUninitialized: false,
    cookie: {
      maxAge: ExpireTime,
    },
  }),
);

// ─── Middleware ───────────────────────────────────────────────────────────────

/** Redirect to /login if not authenticated */
function isAuthenticated(req, res, next) {
  if (req.session.authenticated) {
    return next();
  }
  res.redirect("/login");
}

/** Send 403 if authenticated but not an admin */
function isAdmin(req, res, next) {
  if (req.session.user_type === "admin") {
    return next();
  }
  res.status(403).render("403", {
    authenticated: req.session.authenticated || false,
    user_type: req.session.user_type || "user",
  });
}

// ─── Routes ──────────────────────────────────────────────────────────────────

// Home Page
app.get("/", (req, res) => {
  res.render("index", {
    authenticated: req.session.authenticated || false,
    name: req.session.name || "",
    user_type: req.session.user_type || "",
  });
});

// Sign Up Page
app.get("/signup", (req, res) => {
  res.render("signup", { error: req.query.error || null });
});

// Handle Sign Up form submission
app.post("/submitSignup", async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;

  // Validate with Joi (NoSQL injection protection)
  const schema = Joi.object({
    name: Joi.string().alphanum().max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const { error } = schema.validate({ name, email, password });

  if (error) {
    return res.redirect(
      "/signup?error=" + encodeURIComponent(error.details[0].message),
    );
  }

  // Hash password and insert user (default user_type = "user")
  var hashPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    name: name,
    email: email,
    password: hashPassword,
    user_type: "user",
  });

  // Create session and redirect
  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;
  req.session.user_type = "user";
  res.redirect("/members");
});

// Login Page
app.get("/login", (req, res) => {
  res.render("login", { error: req.query.error || null });
});

// Handle Login form submission
app.post("/submitLogin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  // Validate email with Joi
  const schema = Joi.string().email().required();
  const validationResult = schema.validate(email);

  if (validationResult.error != null) {
    return res.redirect(
      "/login?error=" + encodeURIComponent("Invalid email format."),
    );
  }

  // Query database
  const result = await userCollection.find({ email: email }).toArray();

  if (result.length != 1) {
    return res.redirect(
      "/login?error=" + encodeURIComponent("User not found."),
    );
  }

  // Check password
  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.name = result[0].name;
    req.session.email = result[0].email;
    req.session.user_type = result[0].user_type || "user";
    res.redirect("/members");
  } else {
    return res.redirect(
      "/login?error=" + encodeURIComponent("Invalid password."),
    );
  }
});

// Members Area (requires login)
app.get("/members", isAuthenticated, (req, res) => {
  res.render("members", {
    authenticated: req.session.authenticated,
    name: req.session.name,
    user_type: req.session.user_type || "user",
  });
});

// Admin Page (requires login + admin role)
app.get("/admin", isAuthenticated, isAdmin, async (req, res) => {
  const users = await userCollection.find({}).toArray();
  res.render("admin", {
    authenticated: req.session.authenticated,
    user_type: req.session.user_type,
    users: users,
  });
});

// Promote a user to admin
app.post("/promoteUser", isAuthenticated, isAdmin, async (req, res) => {
  const schema = Joi.string().email().required();
  const validationResult = schema.validate(req.body.email);
  if (validationResult.error != null) return res.redirect("/admin");

  await userCollection.updateOne(
    { email: req.body.email },
    { $set: { user_type: "admin" } },
  );
  res.redirect("/admin");
});

// Demote an admin to regular user
app.post("/demoteUser", isAuthenticated, isAdmin, async (req, res) => {
  const schema = Joi.string().email().required();
  const validationResult = schema.validate(req.body.email);
  if (validationResult.error != null) return res.redirect("/admin");

  await userCollection.updateOne(
    { email: req.body.email },
    { $set: { user_type: "user" } },
  );
  res.redirect("/admin");
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// 403 Forbidden (not an admin)
app.get("/403", (req, res) => {
  res.status(403).render("403", {
    authenticated: req.session.authenticated || false,
    user_type: req.session.user_type || "",
  });
});

// 404 Catch-all
app.use((req, res) => {
  res.status(404).render("404", {
    authenticated: req.session.authenticated || false,
    user_type: req.session.user_type || "",
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
