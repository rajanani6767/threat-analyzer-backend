const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "No token" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, "SECRET_KEY"); // same secret you used
    req.user = decoded;   // 🔥 THIS is important
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid token" });
  }
};