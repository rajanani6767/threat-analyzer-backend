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

    if (otpFails >= 3 || loginFails >= 5) {
      risk = "HIGH";
      percentage = 90;
    } else if (otpFails >= 1 || loginFails >= 3) {
      risk = "MEDIUM";
      percentage = 60;
    }

    res.json({ risk, percentage, otpFails, loginFails });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error calculating risk" });
  }
});

module.exports = router;