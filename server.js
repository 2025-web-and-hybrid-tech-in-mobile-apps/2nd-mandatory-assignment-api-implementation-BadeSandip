const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// In-memory user storage (for simplicity)
const users = {};
const highScores = [];

// Secret key for JWT
const JWT_SECRET = "f3a1e44bcb9a49f8a8f32c6d342f7ad7a6e73968df1b245d108b1f89445698e5"; // Replace with a secure value

// Middleware to verify JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ error: "Missing token" });

    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(401).json({ error: "Invalid token" });
        req.user = user;
        next();
    });
}

// User Signup
app.post("/signup", async (req, res) => {
  const { userHandle, password } = req.body;

  if (!userHandle || !password) {
      return res.status(400).json({ error: "Missing fields" });
  }
  if (userHandle.length < 6) {
      return res.status(400).json({ error: "UserHandle must be at least 6 characters long" });
  }
  if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters long" });
  }
  if (users[userHandle]) {
      return res.status(400).json({ error: "User already exists" });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users[userHandle] = { password: hashedPassword };
  res.status(201).json({ message: "User registered" });
});


// User Login
app.post("/login", async (req, res) => {
  const { userHandle, password, ...extraFields } = req.body;

  // Check if required fields are present
  if (!userHandle || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  // Ensure userHandle and password are strings
  if (typeof userHandle !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Invalid input type" });
  }

  // Reject request if there are unexpected fields
  if (Object.keys(extraFields).length > 0) {
    return res.status(400).json({ error: "Unexpected fields in request" });
  }

  // Check if user exists
  const user = users[userHandle];
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Verify password
  const isPasswordCorrect = await bcrypt.compare(password, user.password);
  if (!isPasswordCorrect) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Generate JWT token
  const token = jwt.sign({ userHandle }, JWT_SECRET, { expiresIn: "1h" });

  res.status(200).json({ jsonWebToken: token });
});



// Submit High Score (protected route)
app.post("/high-scores", authenticateToken, (req, res) => {
    const { level, userHandle, score, timestamp } = req.body;
    if (!level || !userHandle || !score || !timestamp) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    highScores.push({ level, userHandle, score, timestamp });
    res.status(201).json({ message: "High score submitted" });
});

// Get High Scores
app.get("/high-scores", (req, res) => {
    const { level, page = 1 } = req.query;
    if (!level) return res.status(400).json({ error: "Level is required" });

    const filteredScores = highScores
        .filter((hs) => hs.level === level)
        .sort((a, b) => b.score - a.score);

    const pageSize = 20;
    const startIndex = (page - 1) * pageSize;
    const paginatedScores = filteredScores.slice(startIndex, startIndex + pageSize);

    res.status(200).json(paginatedScores);
});

// Start Server
let serverInstance = null;
module.exports = {
    start: function () {
        serverInstance = app.listen(port, () => {
            console.log(`Server running at http://localhost:${port}`);
        });
    },
    close: function () {
        if (serverInstance) serverInstance.close();
    },
};

if (require.main === module) {
  app.listen(port, () => {
      console.log(`Server running at http://localhost:${port}`);
  });
}
