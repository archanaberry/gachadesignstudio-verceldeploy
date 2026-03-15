// serverdeploy/api/manifest.js
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

const app = express();
app.use(helmet());
app.use(express.json());

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: "Too many requests, try again later.",
  })
);

// Allow API key via env or list (recommended to use env var)
const API_KEYS = (process.env.ALLOWED_KEYS || "your-secret-key").split(",");

app.use((req, res, next) => {
  const key = req.headers["x-api-key"] || req.query.api_key;
  if (!API_KEYS.includes(key)) return res.status(403).send("Forbidden");
  next();
});

// Use environment variable for homelab URL
const HOMELAB_MANIFEST_URL =
  process.env.HOMELAB_MANIFEST_URL || "http://100.101.102.103:3000/manifest.json";

app.get("/", async (req, res) => {
  try {
    const r = await fetch(HOMELAB_MANIFEST_URL);
    if (!r.ok) return res.status(502).send("Cannot fetch manifest from homelab");
    const text = await r.text();
    res.setHeader("Content-Type", "application/json");
    res.status(200).send(text);
  } catch (err) {
    console.error("manifest fetch error:", err);
    res.status(500).send("Error fetching manifest");
  }
});

// Export a handler function that Vercel recognizes
export default function handler(req, res) {
  return app(req, res);
}
