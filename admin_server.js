require("dotenv").config({ path: "./.env" });

const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.ADMIN_PORT || 5001;

app.use(cors());
app.use(express.json());

const uri = process.env.MONGO_URI;
if (!uri) {
  console.error("❌ MONGO_URI is not defined in .env file");
  process.exit(1);
}

const client = new MongoClient(uri);
let db,
  usersCollection,
  menuCollection,
  tableCollection,
  eventCollection,
  cartCollection,
  orderCollection,
  offerCollection;
const verificationCodes = {};

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

async function connectDB() {
  try {
    await client.connect();
    db = client.db("RMS");
    usersCollection = db.collection("users");
    menuCollection = db.collection("menu");
    tableCollection = db.collection("tables");
    eventCollection = db.collection("eventHalls");
    cartCollection = db.collection("carts");
    orderCollection = db.collection("orders");
    offerCollection = db.collection("offers");
    console.log("✅ MongoDB is connected");

    const sampleItems = await menuCollection.find().limit(5).toArray();
    sampleItems.forEach((item) => {
      console.log(
        `Startup Check - Item: ${item.name}, Price: ${item.price}, Quantity: ${
          item.quantity || "N/A"
        }`
      );
    });
  } catch (err) {
    console.error("❌ DB Connection Error:", err);
    process.exit(1);
  }
}
connectDB();

const isAdmin = async (req, res, next) => {
  const email =
    req.headers["x-admin-email"] || req.query.email || req.body.email;
  if (req.method === "GET" && !email) {
    console.warn(
      "No email provided for GET request. Proceeding without authentication check."
    );
    return next();
  }
  if (!email) {
    return res.status(403).json({
      success: false,
      message: "Access denied. Admin email is required.",
    });
  }
  const user = await usersCollection.findOne({ email });
  if (!user || !user.isAdmin) {
    return res
      .status(403)
      .json({ success: false, message: "Access denied. Admin only." });
  }
  req.user = user;
  next();
};

// Admin Signup Route
app.post("/admin/signup", async (req, res) => {
  const { name, email, phone, password, adminCode } = req.body;
  const SECRET_ADMIN_CODE = process.env.ADMIN_CODE || "ADMIN123";
  if (adminCode !== SECRET_ADMIN_CODE) {
    return res
      .status(403)
      .json({ success: false, message: "Invalid admin code." });
  }
  if (!name || !email || !phone || !password) {
    return res
      .status(400)
      .json({ success: false, message: "All fields are required." });
  }
  const existing = await usersCollection.findOne({ email });
  if (existing) {
    return res
      .status(400)
      .json({ success: false, message: "User already exists." });
  }
  const hashed = await bcrypt.hash(password, 10);
  const adminUser = {
    name,
    email,
    phone,
    password: hashed,
    isAdmin: true,
  };
  try {
    await usersCollection.insertOne(adminUser);
    res.json({ success: true, message: "Admin registered successfully." });
  } catch (err) {
    console.error("Error registering admin:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error during signup." });
  }
});

// Admin Login Route
app.post("/admin/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await usersCollection.findOne({ email });
  if (!user)
    return res.status(404).json({ success: false, message: "User not found." });
  if (!user.isAdmin)
    return res.status(403).json({ success: false, message: "Not an admin." });
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch)
    return res
      .status(401)
      .json({ success: false, message: "Incorrect password." });
  res.json({
    success: true,
    message: "Admin login successful!",
    email: user.email,
    name: user.name,
  });
});

// Admin OTP & Password Reset Routes
app.post("/admin/forgot", async (req, res) => {
  const { email } = req.body;
  const user = await usersCollection.findOne({ email });
  if (!user || !user.isAdmin)
    return res
      .status(404)
      .json({ success: false, message: "Admin email not found." });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  verificationCodes[email] = code;
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Admin Password Reset Code",
    text: `Your password reset code is: ${code}`,
  });
  res.json({ success: true, message: "Verification code sent." });
});

app.post("/admin/change-password", async (req, res) => {
  const { email, code, newPassword } = req.body;
  if (verificationCodes[email] !== code) {
    return res
      .status(400)
      .json({ success: false, message: "Invalid or expired code." });
  }
  const hashed = await bcrypt.hash(newPassword, 10);
  await usersCollection.updateOne(
    { email, isAdmin: true },
    { $set: { password: hashed } }
  );
  delete verificationCodes[email];
  res.json({ success: true, message: "Password reset successful." });
});

// Menu Routes
app.get("/admin/menu", isAdmin, async (req, res) => {
  try {
    const menuItems = await menuCollection.find().toArray();
    const formattedItems = menuItems.map((item) => {
      const numericPrice =
        typeof item.price === "number"
          ? item.price
          : parseFloat(item.price.replace(/[^0-9.]/g, "")) || 0;
      const numericQuantity =
        item.quantity !== undefined ? parseInt(item.quantity) : 0;
      return {
        ...item,
        price: `₹${numericPrice.toFixed(2)}`,
        quantity: numericQuantity,
      };
    });
    res.json(formattedItems);
  } catch (err) {
    console.error("Error fetching menu items:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error fetching menu items." });
  }
});

app.post("/admin/menu/add", isAdmin, async (req, res) => {
  const { name, category, price, image, quantity } = req.body;
  if (!name || !category || !price || quantity === undefined) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields (name, category, price, quantity).",
    });
  }
  if (isNaN(quantity) || quantity < 0) {
    return res
      .status(400)
      .json({ success: false, message: "Quantity must be a positive number." });
  }
  const menuItem = {
    name,
    category,
    price: parseFloat(price),
    image: image || "",
    quantity: parseInt(quantity),
  };
  try {
    await menuCollection.insertOne(menuItem);
    res.json({
      success: true,
      message: "Menu item added successfully.",
      item: { ...menuItem, price: `₹${menuItem.price.toFixed(2)}` },
    });
  } catch (err) {
    console.error("Error adding menu item:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error adding menu item." });
  }
});

app.put("/admin/menu/update/:id", isAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, category, price, image, quantity } = req.body;
  const updateFields = {};
  if (name) updateFields.name = name;
  if (category) updateFields.category = category;
  if (price) updateFields.price = parseFloat(price);
  if (image) updateFields.image = image;
  if (quantity !== undefined && !isNaN(quantity) && quantity >= 0)
    updateFields.quantity = parseInt(quantity);

  try {
    const result = await menuCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateFields }
    );
    if (result.modifiedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Menu item not found or no changes made.",
      });
    }
    const updatedItem = await menuCollection.findOne({ _id: new ObjectId(id) });
    const numericPrice =
      typeof updatedItem.price === "number"
        ? updatedItem.price
        : parseFloat(updatedItem.price.replace(/[^0-9.]/g, "")) || 0;
    res.json({
      success: true,
      message: "Menu item updated successfully.",
      item: { ...updatedItem, price: `₹${numericPrice.toFixed(2)}` },
    });
  } catch (err) {
    console.error("Error updating menu item:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error updating menu item." });
  }
});

app.put("/admin/menu/update-stock/:id", isAdmin, async (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;
  if (quantity === undefined || isNaN(quantity) || quantity < 0) {
    return res.status(400).json({
      success: false,
      message: "Quantity must be a non-negative number.",
    });
  }

  try {
    const result = await menuCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { quantity: parseInt(quantity) } }
    );
    if (result.modifiedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Menu item not found or no changes made.",
      });
    }
    const updatedItem = await menuCollection.findOne({ _id: new ObjectId(id) });
    res.json({
      success: true,
      message: "Stock updated successfully.",
      item: {
        name: updatedItem.name,
        quantity: updatedItem.quantity,
        price: `₹${(typeof updatedItem.price === "number"
          ? updatedItem.price
          : parseFloat(updatedItem.price.replace(/[^0-9.]/g, "")) || 0
        ).toFixed(2)}`,
      },
    });
  } catch (err) {
    console.error("Error updating stock:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error updating stock." });
  }
});

app.delete("/admin/menu/delete/:id", isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await menuCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Menu item not found." });
    }
    res.json({ success: true, message: "Menu item deleted successfully." });
  } catch (err) {
    console.error("Error deleting menu item:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error deleting menu item." });
  }
});

// Table Routes
app.post("/admin/tables/add", isAdmin, async (req, res) => {
  const { name, capacity, ac, pricePerHour, available, booked } = req.body;
  if (!name || !pricePerHour || !capacity || ac === undefined) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields (name, capacity, ac, pricePerHour).",
    });
  }
  if (available !== undefined && (isNaN(available) || available < 0)) {
    return res.status(400).json({
      success: false,
      message: "Available must be a non-negative integer.",
    });
  }
  const table = {
    name,
    capacity: parseInt(capacity),
    ac: ac === true || ac === "true",
    pricePerHour: parseFloat(pricePerHour),
    available: available !== undefined ? parseInt(available) : 0,
    booked: booked !== undefined ? parseInt(booked) : 0,
  };
  try {
    await tableCollection.insertOne(table);
    res.json({ success: true, message: "Table added successfully.", table });
  } catch (err) {
    console.error("Error adding table:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error adding table." });
  }
});

app.put("/admin/tables/update/:id", isAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, capacity, ac, pricePerHour, available, booked } = req.body;
  if (!name || !pricePerHour || !capacity || ac === undefined) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields (name, capacity, ac, pricePerHour).",
    });
  }
  if (available !== undefined && (isNaN(available) || available < 0)) {
    return res.status(400).json({
      success: false,
      message: "Available must be a non-negative integer.",
    });
  }
  const updateFields = {
    name,
    capacity: parseInt(capacity),
    ac: ac === true || ac === "true",
    pricePerHour: parseFloat(pricePerHour),
    available: available !== undefined ? parseInt(available) : 0,
    booked: booked !== undefined ? parseInt(booked) : 0,
  };

  try {
    const result = await tableCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateFields }
    );
    if (result.modifiedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Table not found or no changes made.",
      });
    }
    const updatedTable = await tableCollection.findOne({
      _id: new ObjectId(id),
    });
    res.json({
      success: true,
      message: "Table updated successfully.",
      table: updatedTable,
    });
  } catch (err) {
    console.error("Error updating table:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error updating table." });
  }
});

app.delete("/admin/tables/delete/:id", isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await tableCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Table not found." });
    }
    res.json({ success: true, message: "Table deleted successfully." });
  } catch (err) {
    console.error("Error deleting table:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error deleting table." });
  }
});

// Event Hall Routes
app.post("/admin/eventhalls/add", isAdmin, async (req, res) => {
  const { name, capacity, pricePerHour, available } = req.body;
  if (!name || !capacity || !pricePerHour) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields (name, capacity, pricePerHour).",
    });
  }
  const eventHall = {
    name,
    capacity: parseInt(capacity),
    pricePerHour: parseFloat(pricePerHour),
    available: available !== undefined ? available : true,
  };
  try {
    await eventCollection.insertOne(eventHall);
    res.json({
      success: true,
      message: "Event hall added successfully.",
      eventHall,
    });
  } catch (err) {
    console.error("Error adding event hall:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error adding event hall." });
  }
});

app.put("/admin/eventhalls/update/:id", isAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, capacity, pricePerHour, available } = req.body;
  const updateFields = {};
  if (name) updateFields.name = name;
  if (capacity) updateFields.capacity = parseInt(capacity);
  if (pricePerHour) updateFields.pricePerHour = parseFloat(pricePerHour);
  if (available !== undefined) updateFields.available = available;

  try {
    const result = await eventCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateFields }
    );
    if (result.modifiedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Event hall not found or no changes made.",
      });
    }
    const updatedEventHall = await eventCollection.findOne({
      _id: new ObjectId(id),
    });
    res.json({
      success: true,
      message: "Event hall updated successfully.",
      eventHall: updatedEventHall,
    });
  } catch (err) {
    console.error("Error updating event hall:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error updating event hall." });
  }
});

app.delete("/admin/eventhalls/delete/:id", isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await eventCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Event hall not found." });
    }
    res.json({ success: true, message: "Event hall deleted successfully." });
  } catch (err) {
    console.error("Error deleting event hall:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error deleting event hall." });
  }
});

// Offer Routes
app.post("/admin/offers/add", isAdmin, async (req, res) => {
  const { itemId, offerPrice } = req.body;
  if (!itemId || !offerPrice) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields (itemId, offerPrice).",
    });
  }
  try {
    const menuItem = await menuCollection.findOne({
      _id: new ObjectId(itemId),
    });
    if (!menuItem) {
      return res
        .status(404)
        .json({ success: false, message: "Menu item not found." });
    }
    const rawPrice =
      menuItem.price !== undefined && menuItem.price !== null
        ? menuItem.price.toString()
        : "0";
    const originalPrice = Number(rawPrice.replace(/[^0-9.-]+/g, ""));
    if (isNaN(originalPrice) || originalPrice <= 0) {
      console.error(
        `Invalid original price for item ${menuItem.name}: ${rawPrice}, _id: ${menuItem._id}`
      );
      return res.status(400).json({
        success: false,
        message: `Invalid original price for ${menuItem.name}`,
      });
    }
    const offer = {
      itemId: new ObjectId(itemId),
      itemName: menuItem.name,
      originalPrice: originalPrice,
      offerPrice: parseFloat(offerPrice),
      createdAt: new Date(),
    };
    await offerCollection.insertOne(offer);
    res.json({ success: true, message: "Offer added successfully.", offer });
  } catch (err) {
    console.error("Error adding offer:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error adding offer." });
  }
});

app.put("/admin/offers/update/:id", isAdmin, async (req, res) => {
  const { id } = req.params;
  const { offerPrice } = req.body;
  if (!offerPrice) {
    return res
      .status(400)
      .json({ success: false, message: "Offer price is required." });
  }
  try {
    const result = await offerCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { offerPrice: parseFloat(offerPrice), updatedAt: new Date() } }
    );
    if (result.modifiedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Offer not found or no changes made.",
      });
    }
    const updatedOffer = await offerCollection.findOne({
      _id: new ObjectId(id),
    });
    res.json({
      success: true,
      message: "Offer updated successfully.",
      offer: updatedOffer,
    });
  } catch (err) {
    console.error("Error updating offer:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error updating offer." });
  }
});

app.delete("/admin/offers/delete/:id", isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await offerCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Offer not found." });
    }
    res.json({ success: true, message: "Offer deleted successfully." });
  } catch (err) {
    console.error("Error deleting offer:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error deleting offer." });
  }
});

app.get("/admin/offers", isAdmin, async (req, res) => {
  try {
    const offers = await offerCollection.find().toArray();
    res.json(offers);
  } catch (err) {
    console.error("Error fetching offers:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error fetching offers." });
  }
});

// Admin Logout Route
app.post("/admin/logout", (req, res) => {
  res.json({ success: true, message: "Admin logout successful." });
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Admin Server running on port ${PORT}`);
});
