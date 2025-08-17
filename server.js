require("dotenv").config({
  path: process.env.NODE_ENV === "test" ? ".env.test" : ".env",
});

const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use("/images", express.static(path.join(__dirname, "images")));

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
    db = client.db(process.env.NODE_ENV === "test" ? "rms-test" : "RMS");
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

// Authentication Routes
app.post("/signup", async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }
  try {
    const existing = await usersCollection.findOne({ email });
    if (existing)
      return res.status(400).json({ message: "User already exists" });
    const hashed = await bcrypt.hash(password, 10);
    await usersCollection.insertOne({ name, email, phone, password: hashed });
    res.json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Error during signup:", err);
    res.status(500).json({ message: "Server error during signup" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Incorrect password" });
    res.json({
      message: "Login successful",
      email: user.email,
      name: user.name,
    });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ message: "Server error during login" });
  }
});

// OTP & Password Reset Routes
app.post("/forgot", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(404).json({ message: "Email not found" });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const timestamp = Date.now();
    verificationCodes[email] = { code, timestamp };
    console.log(
      `Debug - Code generated for ${email}: ${code}, Timestamp: ${timestamp}`
    );
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset Code",
      text: `Your password reset code is: ${code}. It will expire in 10 minutes.`,
    });
    res.json({ message: "Verification code sent" });
  } catch (err) {
    console.error("Error sending reset code:", err);
    res.status(500).json({ message: "Server error sending reset code" });
  }
});

app.post("/send-code", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(404).json({ message: "Email not registered" });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const timestamp = Date.now();
    verificationCodes[email] = { code, timestamp };
    console.log(
      `Debug - OTP generated for ${email}: ${code}, Timestamp: ${timestamp}`
    );
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your OTP Code",
      text: `Your verification code is: ${code}. It will expire in 10 minutes.`,
    });
    res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("Error sending OTP:", err);
    res.status(500).json({ message: "Server error sending OTP" });
  }
});

app.post("/change-password", async (req, res) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword) {
    return res
      .status(400)
      .json({ message: "Email and new password are required" });
  }
  try {
    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });
    const hashed = await bcrypt.hash(newPassword, 10);
    const result = await usersCollection.updateOne(
      { email },
      { $set: { password: hashed } }
    );
    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: "No changes made" });
    }
    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("Error resetting password:", err);
    res.status(500).json({ message: "Server error resetting password" });
  }
});

app.post("/verify-code", async (req, res) => {
  const { email, code } = req.body;
  try {
    const stored = verificationCodes[email];
    if (
      !stored ||
      stored.code !== code ||
      Date.now() - stored.timestamp > 10 * 60 * 1000
    ) {
      return res.status(400).json({ message: "Invalid or expired code" });
    }
    res.json({ message: "Code verified successfully" });
  } catch (err) {
    console.error("Error verifying code:", err);
    res.status(500).json({ message: "Server error verifying code" });
  }
});

// Menu Routes
app.get("/menu", async (req, res) => {
  try {
    const menuItems = await menuCollection.find().toArray();
    if (!menuItems || menuItems.length === 0) {
      return res.status(404).json({ message: "No menu items available" });
    }

    const offers = await offerCollection.find().toArray();
    const offersMap = offers.reduce((acc, offer) => {
      const offerPrice = Number(offer.offerPrice);
      if (!isNaN(offerPrice) && offerPrice > 0) {
        acc[offer.itemId.toString()] = offerPrice;
      } else {
        console.warn(
          `Invalid offer price for item ${offer.itemId}: ${offer.offerPrice}`
        );
      }
      return acc;
    }, {});

    const menuWithOffers = menuItems.map((item) => {
      const rawPrice = item.price || "0";
      const price = Number(rawPrice.toString().replace(/[^0-9.-]+/g, ""));
      const offerPrice = offersMap[item._id.toString()] || null;

      if (isNaN(price) || price <= 0) {
        console.error(
          `Invalid price for item ${item.name}: ${rawPrice}, _id: ${item._id}`
        );
        return {
          ...item,
          price: 0,
          offerPrice: null,
          quantity: item.quantity || 0,
        };
      }

      return {
        ...item,
        price,
        offerPrice:
          offerPrice !== null && !isNaN(offerPrice) && offerPrice > 0
            ? offerPrice
            : null,
        quantity: item.quantity || 0,
      };
    });

    const userMenu = menuWithOffers.map((item) => ({
      _id: item._id,
      name: item.name,
      category: item.category,
      price: item.price,
      offerPrice: item.offerPrice,
      image: item.image || "",
      quantity: item.quantity,
    }));

    res.json(userMenu);
  } catch (err) {
    console.error("Error fetching menu:", err.stack);
    res
      .status(500)
      .json({ message: "Server error fetching menu", error: err.message });
  }
});

app.get("/menu/name/:name", async (req, res) => {
  const { name } = req.params;
  try {
    const item = await menuCollection.findOne({
      name: new RegExp(`^${name}$`, "i"),
    });
    if (!item) {
      console.log(`No item found for name: ${name}`);
      return res.status(404).json({ message: "Menu item not found" });
    }
    const rawPrice =
      item.price !== undefined && item.price !== null
        ? item.price.toString()
        : "0";
    const price = Number(rawPrice.replace(/[^0-9.-]+/g, ""));
    if (isNaN(price) || price <= 0) {
      console.error(
        `Invalid price for item ${item.name}: ${rawPrice}, _id: ${item._id}`
      );
      return res
        .status(400)
        .json({ message: `Invalid price for ${item.name}` });
    }
    const { quantity, ...userItem } = item;
    res.json({ ...userItem, price });
  } catch (err) {
    console.error("Error fetching menu item by name:", err);
    res.status(500).json({ message: "Server error fetching menu item" });
  }
});

app.get("/menu/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const item = await menuCollection.findOne({ _id: new ObjectId(id) });
    if (!item) return res.status(404).json({ message: "Menu item not found" });
    const offer = await offerCollection.findOne({ itemId: new ObjectId(id) });
    const rawPrice = item.price || "0";
    const price = Number(rawPrice.toString().replace(/[^0-9.-]+/g, ""));

    if (isNaN(price) || price <= 0) {
      console.error(
        `Invalid price for item ${item.name}: ${rawPrice}, _id: ${item._id}`
      );
      return res
        .status(400)
        .json({ message: `Invalid price for ${item.name}` });
    }

    const { quantity, ...userItem } = item;
    res.json({
      ...userItem,
      price,
      offerPrice: offer
        ? Number(offer.offerPrice.replace(/[^0-9.-]+/g, ""))
        : null,
    });
  } catch (err) {
    console.error("Error fetching menu item:", err);
    res.status(500).json({ message: "Server error fetching menu item" });
  }
});

// Table and Event Hall Routes
app.get("/tables", async (req, res) => {
  try {
    const tables = await tableCollection.find().toArray();
    res.json(tables);
  } catch (err) {
    console.error("Error fetching tables:", err);
    res.status(500).json({ message: "Server error fetching tables" });
  }
});

app.get("/eventhalls", async (req, res) => {
  try {
    const halls = await eventCollection.find().toArray();
    res.json(halls);
  } catch (err) {
    console.error("Error fetching event halls:", err);
    res.status(500).json({ message: "Server error fetching event halls" });
  }
});

// Cart API
app.post("/cart/add", async (req, res) => {
  const { email, itemId, name, price, quantity, itemType } = req.body;

  if (!email || !itemId || !name || price == null || !quantity || !itemType) {
    return res.status(400).json({
      success: false,
      message: `Missing or invalid item data: ${JSON.stringify({
        email: !!email,
        itemId: !!itemId,
        name: !!name,
        price: price != null,
        quantity: !!quantity,
        itemType: !!itemType,
      })}`,
    });
  }

  try {
    let effectivePrice = Number(price);
    if (isNaN(effectivePrice) || effectivePrice <= 0) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid price value" });
    }

    if (itemType === "menu") {
      const menuItem = await menuCollection.findOne({
        _id: new ObjectId(itemId),
      });
      if (!menuItem) {
        return res
          .status(404)
          .json({ success: false, message: "Menu item not found" });
      }
      if (menuItem.quantity < quantity) {
        return res.status(400).json({
          success: false,
          message: `Insufficient stock for ${menuItem.name}. Available: ${menuItem.quantity}`,
        });
      }

      const offer = await offerCollection.findOne({
        itemId: new ObjectId(itemId),
      });
      if (
        offer &&
        !isNaN(Number(offer.offerPrice)) &&
        Number(offer.offerPrice) > 0
      ) {
        effectivePrice = Number(offer.offerPrice);
      }

      await menuCollection.updateOne(
        { _id: new ObjectId(itemId) },
        { $inc: { quantity: -quantity } }
      );
    } else if (itemType === "table") {
      const table = await tableCollection.findOne({
        _id: new ObjectId(itemId),
      });
      if (!table) {
        return res
          .status(404)
          .json({ success: false, message: "Table not found" });
      }
      if (table.available < quantity) {
        return res.status(400).json({
          success: false,
          message: `Table ${table.name} has insufficient availability. Available: ${table.available}`,
        });
      }
      await tableCollection.updateOne(
        { _id: new ObjectId(itemId) },
        { $inc: { available: -quantity } }
      );
    } else if (itemType === "eventhall") {
      const hall = await eventCollection.findOne({ _id: new ObjectId(itemId) });
      if (!hall) {
        return res
          .status(404)
          .json({ success: false, message: "Event hall not found" });
      }
      if (!hall.available) {
        return res.status(400).json({
          success: false,
          message: `Event hall ${hall.name} is not available`,
        });
      }
      await eventCollection.updateOne(
        { _id: new ObjectId(itemId) },
        { $set: { available: false } }
      );
    } else {
      return res
        .status(400)
        .json({ success: false, message: `Invalid item type: ${itemType}` });
    }

    let userCart = await cartCollection.findOne({ email });

    if (userCart) {
      const itemIndex = userCart.items.findIndex(
        (item) => item._id === itemId && item.itemType === itemType
      );
      if (itemIndex > -1) {
        userCart.items[itemIndex].quantity += quantity;
      } else {
        userCart.items.push({
          _id: itemId,
          name,
          price: effectivePrice,
          quantity,
          itemType,
        });
      }
      userCart.totalCost = userCart.items.reduce(
        (acc, item) => acc + item.price * item.quantity,
        0
      );
      await cartCollection.updateOne(
        { email },
        { $set: { items: userCart.items, totalCost: userCart.totalCost } }
      );
    } else {
      const newCart = {
        email,
        items: [
          { _id: itemId, name, price: effectivePrice, quantity, itemType },
        ],
        totalCost: effectivePrice * quantity,
      };
      await cartCollection.insertOne(newCart);
    }

    const updatedCart = await cartCollection.findOne({ email });
    if (!updatedCart) {
      return res
        .status(500)
        .json({ success: false, message: "Failed to retrieve updated cart" });
    }

    res.json({
      success: true,
      message: "Item added successfully",
      cart: updatedCart,
    });
  } catch (error) {
    console.error("Error in /cart/add:", error);
    if (itemType === "menu") {
      await menuCollection.updateOne(
        { _id: new ObjectId(itemId) },
        { $inc: { quantity: quantity } }
      );
    }
    res
      .status(500)
      .json({ success: false, message: `Server error: ${error.message}` });
  }
});

app.get("/cart/:email", async (req, res) => {
  const email = req.params.email;
  try {
    const userCart = await cartCollection.findOne({ email });
    if (!userCart) {
      return res.json({ items: [], totalCost: 0 });
    }
    res.json({ items: userCart.items, totalCost: userCart.totalCost });
  } catch (error) {
    console.error("Error fetching cart:", error);
    res.status(500).json({ message: "Error fetching cart", error });
  }
});

app.put("/cart/:email/:itemId", async (req, res) => {
  const { email, itemId } = req.params;
  const { change, itemType } = req.body;

  try {
    const userCart = await cartCollection.findOne({ email });
    if (!userCart) {
      return res.status(404).json({ message: "Cart not found" });
    }

    const itemIndex = userCart.items.findIndex(
      (item) => item._id === itemId && item.itemType === itemType
    );
    if (itemIndex === -1) {
      return res.status(404).json({ message: "Item not in cart" });
    }

    const item = userCart.items[itemIndex];
    const newQty = item.quantity + change;

    if (itemType === "menu" && change > 0) {
      const menuItem = await menuCollection.findOne({
        _id: new ObjectId(itemId),
      });
      if (!menuItem || menuItem.quantity < change) {
        return res.status(400).json({ message: "Insufficient stock" });
      }
      await menuCollection.updateOne(
        { _id: new ObjectId(itemId) },
        { $inc: { quantity: -change } }
      );
    }

    if (newQty <= 0) {
      if (itemType === "table") {
        await tableCollection.updateOne(
          { _id: new ObjectId(itemId) },
          { $inc: { available: item.quantity } }
        );
      } else if (itemType === "eventhall") {
        await eventCollection.updateOne(
          { _id: new ObjectId(itemId) },
          { $set: { available: true } }
        );
      } else if (itemType === "menu") {
        await menuCollection.updateOne(
          { _id: new ObjectId(itemId) },
          { $inc: { quantity: item.quantity } }
        );
      }
      userCart.items.splice(itemIndex, 1);
      userCart.totalCost -= item.price * item.quantity;
    } else {
      userCart.items[itemIndex].quantity = newQty;
      userCart.totalCost += item.price * change;
    }

    await cartCollection.updateOne(
      { email },
      { $set: { items: userCart.items, totalCost: userCart.totalCost } },
      { upsert: true }
    );
    res.json({ message: "Cart updated" });
  } catch (error) {
    console.error("Error updating cart:", error);
    res
      .status(500)
      .json({ message: "Error updating cart", error: error.message });
  }
});

// Offers
app.get("/offers", async (req, res) => {
  try {
    const offers = await offerCollection.find().toArray();
    if (!offers || offers.length === 0) {
      return res.json([]);
    }

    const offerItemNames = offers
      .filter(
        (offer) =>
          offer.itemName &&
          typeof offer.itemName === "string" &&
          offer.itemName.trim()
      )
      .map((offer) => offer.itemName.trim());

    if (offerItemNames.length === 0) {
      console.warn("No valid itemNames found in offers");
      return res.json([]);
    }

    const menuItems = await menuCollection
      .find({ name: { $in: offerItemNames } })
      .toArray();
    console.log(
      `Fetched ${menuItems.length} menu items for ${offerItemNames.length} unique offer itemNames`
    );

    const menuMap = menuItems.reduce((acc, item) => {
      const key = item.name.trim().toLowerCase();
      if (!acc[key]) {
        acc[key] = item;
      } else {
        console.warn(`Multiple menu items found for name: ${item.name}`);
      }
      return acc;
    }, {});

    const enrichedOffers = offers.map((offer) => {
      if (
        !offer.itemName ||
        typeof offer.itemName !== "string" ||
        !offer.itemName.trim()
      ) {
        console.warn("Skipping offer with invalid itemName:", offer);
        return null;
      }

      const menuItem = menuMap[offer.itemName.trim().toLowerCase()];
      if (!menuItem) {
        console.warn(
          `No menu item found for offer itemName: ${offer.itemName}`
        );
      }

      let originalPrice = 0;
      let offerPrice = 0;

      try {
        if (typeof offer.originalPrice === "string") {
          originalPrice =
            parseFloat(offer.originalPrice.replace(/[^0-9.]/g, "")) || 0;
        } else if (typeof offer.originalPrice === "number") {
          originalPrice = offer.originalPrice;
        }

        if (typeof offer.offerPrice === "string") {
          offerPrice =
            parseFloat(offer.offerPrice.replace(/[^0-9.]/g, "")) || 0;
        } else if (typeof offer.offerPrice === "number") {
          offerPrice = offer.offerPrice;
        }
      } catch (e) {
        console.error(
          `Price parsing error for ${offer.itemName || "Unknown"}:`,
          e.message
        );
      }

      const imageUrl =
        menuItem &&
        menuItem.image &&
        typeof menuItem.image === "string" &&
        menuItem.image.trim()
          ? menuItem.image
          : "https://via.placeholder.com/100";

      return {
        _id: offer._id,
        itemId: menuItem ? menuItem._id.toString() : null,
        itemName: offer.itemName,
        originalPrice: `₹${originalPrice.toFixed(2)}`,
        offerPrice: `₹${offerPrice.toFixed(2)}`,
        image: imageUrl,
      };
    });

    const validOffers = enrichedOffers.filter(
      (offer) =>
        offer !== null && offer.image !== "https://via.placeholder.com/100"
    );
    console.log(`Returning ${validOffers.length} valid offers`);
    res.json(
      validOffers.length > 0
        ? validOffers
        : enrichedOffers.filter((offer) => offer !== null)
    );
  } catch (err) {
    console.error("Error in /offers endpoint:", err.stack);
    res
      .status(500)
      .json({ message: "Server error fetching offers", error: err.message });
  }
});

// Order API
app.post("/order", async (req, res) => {
  const { email } = req.body;
  try {
    const cart = await cartCollection.findOne({ email });
    if (!cart || !cart.items.length)
      return res.status(400).json({ message: "Cart is empty" });

    const orderItems = cart.items;
    const total = orderItems.reduce(
      (acc, item) => acc + item.price * item.quantity,
      0
    );

    await orderCollection.insertOne({
      email,
      items: orderItems,
      total,
      createdAt: new Date(),
    });
    await cartCollection.deleteOne({ email });
    res.json({ message: "Order placed successfully" });
  } catch (err) {
    console.error("Error placing order:", err);
    res.status(500).json({ message: "Server error placing order" });
  }
});

app.get("/orders/:email", async (req, res) => {
  const userEmail = req.params.email;
  if (!userEmail) {
    return res.status(400).json({ message: "Email parameter is missing" });
  }
  try {
    const orders = await orderCollection.find({ email: userEmail }).toArray();
    res.json(orders);
  } catch (err) {
    console.error("Error fetching user orders:", err);
    res.status(500).json({ message: "Failed to fetch orders" });
  }
});

// Logout
app.post("/logout", (req, res) => {
  res.json({ message: "Logout successful" });
});

// Server Start
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
module.exports = app;
