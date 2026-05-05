const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

const analyticsRoutes = require("./routes/analytics");
app.use("/api", analyticsRoutes);

app.get("/", (req, res) => {
  res.send("Threat Analyzer Running 🚀");
});

const PORT = process.env.PORT || 5001;

app.listen(PORT, () => {
  console.log("Server running on", PORT);
});