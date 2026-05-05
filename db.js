const { Client } = require("pg");

const db = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

db.connect()
  .then(() => console.log("DB Connected ✅"))
  .catch(err => console.log("DB ERROR 👉", err));

module.exports = db;