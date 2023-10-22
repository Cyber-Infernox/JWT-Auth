const jwt = require("jsonwebtoken");
const cors = require("cors");
const express = require("express");
const app = express();

const dotenv = require("dotenv");
dotenv.config();

app.use(express.json()); // For post requests
app.use(cors());

const users = [
  {
    id: "1",
    username: "John",
    password: "John0908",
    isAdmin: true,
  },
  {
    id: "2",
    username: "James",
    password: "James0908",
    isAdmin: false,
  },
];

let refreshTokens = [];

app.post("/api/refresh", (req, res) => {
  // Take the refresh token from the user
  const refreshToken = req.body.token;

  // Send error if there is no token or it's invalid
  if (!refreshToken) return res.status(401).json("You are not authenticated");
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json("Refresh token is not valid");
  }

  // If there is no error, create new access token, refresh token and send\ it to the user
  jwt.verify(refreshToken, process.env.REFRESH_KEY, (err, user) => {
    if (err) {
      console.log(err);
    }

    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    refreshTokens.push(newRefreshToken);

    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });
});

const generateAccessToken = (user) => {
  return jwt.sign(
    { id: user.id, isAdmin: user.isAdmin },
    process.env.ACCESS_KEY,
    {
      expiresIn: process.env.ACCESS_KEY_EXPIRY,
    }
  );
};

const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user.id, isAdmin: user.isAdmin },
    process.env.REFRESH_KEY
  );
};

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => {
    return u.username === username && u.password === password;
  });
  if (user) {
    // Generate and access token
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);
    res.json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
    });
    // res.json(user);
  } else {
    res.status(400).json("Invalid username or password");
  }
});

// Middleware to verify JWT before deleting
const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, process.env.ACCESS_KEY, (err, user) => {
      if (err) {
        return res.status(403).json("Token is not valid!");
      }

      req.user = user;
      next();
    });
  } else {
    res.status(401).json("You are not authenticated!");
  }
};

app.delete("/api/users/:userId", verify, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.status(200).json("User has been deleted");
  } else {
    res.status(403).json("You are not allowed to delete this user");
  }
});

app.post("/api/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  if (!refreshToken) return res.status(401).json("You are not authenticated");

  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.status(200).json("You logged out successfully");
});

app.listen(process.env.PORT, () => {
  console.log("Server is running!");
});
