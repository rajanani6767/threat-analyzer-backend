const express = require("express");
const router = express.Router();
const db = require("../db");
const adminMiddleware = require("../middleware/adminMiddleware");
const authMiddleware = require("../middleware/authMiddleware");


// ================= GLOBAL RISK (for dashboard) =================
router.get("/risk", async (req, res) => {
  try {
    const result = await db.query(
      "SELECT * FROM security_logs WHERE created_at >= NOW() - INTERVAL '30 minutes'"
    );

    let otpFails = 0;
    let loginFails = 0;

    result.rows.forEach(log => {
      if (log.event === "otp_failed") otpFails++;
      if (log.event === "login_failed") loginFails++;
    });

    let risk = "LOW";
    let percentage = 10;
    let alert = "Normal";

    // 🔥 Detection Logic
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


// ================= PER USER ANALYSIS =================
router.get("/user-risk", async (req, res) => {
  try {
    const result = await db.query(`
      SELECT email, event, COUNT(*) as count
      FROM security_logs
      WHERE event IN ('login_failed','otp_failed')
        AND created_at >= NOW() - INTERVAL '30 minutes'
      GROUP BY email, event
    `);

    const users = {};

    // 🔹 Build user-wise data
    result.rows.forEach(row => {
      if (!users[row.email]) {
        users[row.email] = {
          email: row.email,
          otpFails: 0,
          loginFails: 0
        };
      }

      if (row.event === "otp_failed") {
        users[row.email].otpFails = parseInt(row.count);
      }

      if (row.event === "login_failed") {
        users[row.email].loginFails = parseInt(row.count);
      }
    });

    // 🔹 Calculate risk per user
    const userRiskList = Object.values(users).map(user => {
      let risk = "LOW";
      let percentage = 10;
      let alert = "Normal";

      if (user.loginFails >= 5) {
        risk = "HIGH";
        percentage = 95;
        alert = "Brute Force 🚨";
      }
      else if (user.otpFails >= 3) {
        risk = "HIGH";
        percentage = 85;
        alert = "OTP Failures 🚨";
      }
      else if (user.loginFails >= 2 || user.otpFails >= 1) {
        risk = "MEDIUM";
        percentage = 60;
        alert = "Suspicious ⚠️";
      }

      return {
        ...user,
        risk,
        percentage,
        alert
      };
    });

    res.json(userRiskList);

  } catch (err) {
    res.status(500).json({ error: "Error calculating user risk" });
  }
});


// ================= ADMIN: HIGH RISK USERS =================
router.get("/admin/high-risk", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT email, event, COUNT(*) as count
      FROM security_logs
      WHERE event IN ('login_failed','otp_failed')
        AND created_at >= NOW() - INTERVAL '30 minutes'
      GROUP BY email, event
    `);

    const users = {};

    result.rows.forEach(row => {
      if (!users[row.email]) {
        users[row.email] = {
          email: row.email,
          otpFails: 0,
          loginFails: 0
        };
      }

      if (row.event === "otp_failed") {
        users[row.email].otpFails = parseInt(row.count);
      }

      if (row.event === "login_failed") {
        users[row.email].loginFails = parseInt(row.count);
      }
    });

    // 🔥 Filter ONLY HIGH risk users
    const highRiskUsers = Object.values(users).map(user => {

      let risk = "LOW";
      let percentage = 10;

      if (user.loginFails >= 5) {
        risk = "HIGH";
        percentage = 95;
      }
      else if (user.otpFails >= 3) {
        risk = "HIGH";
        percentage = 85;
      }

      return {
        ...user,
        risk,
        percentage
      };

    }).filter(user => user.risk === "HIGH");

    res.json(highRiskUsers);

  } catch (err) {
    res.status(500).json({ error: "Error fetching high risk users" });
  }
});


module.exports = router;