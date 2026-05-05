const express = require("express");
const router = express.Router();
const db = require("../db");

router.get("/risk", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM security_logs");

    let otpFails = 0;
    let loginFails = 0;

    result.rows.forEach(log => {
      if (log.event === "otp_failed") otpFails++;
      if (log.event === "login_failed") loginFails++;
    });

    let risk = "LOW";
    let percentage = 10;
    let alert = "Normal";

    // 🔥 Brute force detection
    if (loginFails >= 5) {
      risk = "HIGH";
      percentage = 95;
      alert = "Brute Force Attack Detected 🚨";
    }
    else if (otpFails >= 3) {
      risk = "HIGH";
      percentage = 85;
      alert = "Multiple OTP Failures 🚨";
    }
    else if (loginFails >= 2 || otpFails >= 1) {
      risk = "MEDIUM";
      percentage = 60;
      alert = "Suspicious Activity ⚠️";
    }

    res.json({
      risk,
      percentage,
      otpFails,
      loginFails,
      alert
    });

  } catch (err) {
    res.status(500).json({ error: "Error calculating risk" });
  }
});
router.get("/users", async (req, res) => {
  try {
    const result = await db.query(`
      SELECT email, event, COUNT(*) as count
      FROM security_logs
      WHERE event IN ('login_failed','otp_failed')
      GROUP BY email, event
      ORDER BY count DESC
    `);

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Error fetching users" });
  }
});

module.exports = router;