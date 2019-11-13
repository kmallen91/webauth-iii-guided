const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Users = require("../users/users-model.js");

module.exports = (req, res, next) => {
  const token = req.headers.authorization;

  if (token) {
    const secret = process.env.JWT_SECRET || "keep it secret";

    // check that token is valid
    jwt.verify(token, secret, (error, decodedToken) => {
      if (err) {
        //bad token, token has been tampered with
        res.status(401).json({ message: `bad token` });
      } else {
        req.decodedJwt = decodedToken;
        next();
      }
    });
  } else {
    res.status(400).json({ message: "No credentials provided" });
  }
};
