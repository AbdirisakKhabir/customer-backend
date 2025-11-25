const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.post("/api/register", async (req, res) => {
  const { name, phone, address } = req.body;

  if (!name || !phone || !address) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
    const newCustomer = await prisma.customer.create({
      data: {
        name,
        phone,
        address,
      },
    });
    res.status(201).json(newCustomer);
  } catch (error) {
    console.error("Registration error:", error);
    // Handle unique constraint violation (if phone exists)
    if (error.code === "P2002") {
      return res
        .status(409)
        .json({ error: "A customer with this phone number already exists." });
    }
    res
      .status(500)
      .json({ error: "Internal server error during registration." });
  }
});

app.listen(PORT, () => {
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
});

// Graceful shutdown
process.on("SIGINT", async () => {
  console.log("\n🛑 Shutting down server...");
  await prisma.$disconnect();
  process.exit(0);
});

module.exports = app;
