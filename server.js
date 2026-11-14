
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Stripe = require("stripe");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

const stripe = process.env.STRIPE_SECRET_KEY
  ? Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

app.use(cors());

app.get("/", (req, res) => {
  res.send("Progree Secure E-Commerce API is running!");
});

app.get("/api/health", (req, res) => {
  res.json({ status: "OK", project: "Progree E-Commerce" });
});

app.use(express.json());

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password || password.length < 8) {
      return res.status(400).json({
        error: "Enter name, email and a password of at least 8 characters."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await pool.query(
      "INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email",
      [name, email.toLowerCase(), hashedPassword]
    );

    res.status(201).json({
      message: "Registration successful",
      user: result.rows[0]
    });
  } catch (error) {
    res.status(400).json({ error: "Registration failed. Email may already exist." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email.toLowerCase()]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ error: "Login required" });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (error) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

app.get("/api/products", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id,name,description,price,stock FROM products ORDER BY id"
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: "Could not load products" });
  }
});

app.get("/api/cart", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.product_id,c.quantity,p.name,p.price,p.stock
       FROM cart_items c JOIN products p ON p.id=c.product_id
       WHERE c.user_id=$1`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: "Could not load cart" });
  }
});

app.post("/api/cart", authenticate, async (req, res) => {
  try {
    const { product_id, quantity } = req.body;

    if (!Number.isInteger(quantity) || quantity < 1) {
      return res.status(400).json({ error: "Quantity must be a positive integer" });
    }

    const product = await pool.query(
      "SELECT id,stock FROM products WHERE id=$1",
      [product_id]
    );

    if (!product.rows.length || product.rows[0].stock < quantity) {
      return res.status(400).json({ error: "Product unavailable or insufficient stock" });
    }

    await pool.query(
      `INSERT INTO cart_items(user_id,product_id,quantity)
       VALUES($1,$2,$3)
       ON CONFLICT(user_id,product_id)
       DO UPDATE SET quantity=cart_items.quantity + EXCLUDED.quantity`,
      [req.user.id, product_id, quantity]
    );

    res.json({ message: "Cart updated" });
  } catch (error) {
    res.status(500).json({ error: "Could not update cart" });
  }
});

app.delete("/api/cart/:productId", authenticate, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM cart_items WHERE user_id=$1 AND product_id=$2",
      [req.user.id, req.params.productId]
    );
    res.json({ message: "Item removed from cart" });
  } catch (error) {
    res.status(500).json({ error: "Could not remove item" });
  }
});

app.post("/api/checkout", authenticate, async (req, res) => {
  if (!stripe) {
    return res.status(503).json({ error: "Payment sandbox is not configured yet" });
  }

  try {
    const cart = await pool.query(
      `SELECT p.id,p.name,p.price,p.stock,c.quantity
       FROM cart_items c JOIN products p ON p.id=c.product_id
       WHERE c.user_id=$1`,
      [req.user.id]
    );

    if (!cart.rows.length) {
      return res.status(400).json({ error: "Your cart is empty" });
    }

    for (const item of cart.rows) {
      if (item.quantity > item.stock) {
        return res.status(400).json({ error: "Insufficient stock for " + item.name });
      }
    }

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: cart.rows.map(item => ({
        price_data: {
          currency: "inr",
          product_data: { name: item.name },
          unit_amount: Math.round(Number(item.price) * 100)
        },
        quantity: item.quantity
      })),
      success_url: `${process.env.FRONTEND_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/cancel.html`
    });

    res.json({ checkoutUrl: session.url });
  } catch (error) {
    res.status(500).json({ error: "Checkout could not be started" });
  }
});

// Stripe webhook: inventory is reduced only after verified payment.
app.post("/api/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(503).send("Webhook is not configured");
  }

  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (error) {
    return res.status(400).send("Invalid webhook signature");
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const userId = Number(session.client_reference_id);
      if (!userId) throw new Error("Missing user reference");

      const cart = await client.query(
        `SELECT c.product_id,c.quantity,p.stock
         FROM cart_items c JOIN products p ON p.id=c.product_id
         WHERE c.user_id=$1 FOR UPDATE`,
        [userId]
      );

      for (const item of cart.rows) {
        if (item.quantity > item.stock) {
          throw new Error("Insufficient inventory");
        }
        await client.query(
          "UPDATE products SET stock=stock-$1 WHERE id=$2",
          [item.quantity, item.product_id]
        );
      }

      await client.query("DELETE FROM cart_items WHERE user_id=$1", [userId]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("Inventory update failed:", error.message);
    } finally {
      client.release();
    }
  }

  res.json({ received: true });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
      
