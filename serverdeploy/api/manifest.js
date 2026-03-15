import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

const app = express();
app.use(helmet());
app.use(rateLimit({ windowMs: 15*60*1000, max: 100 }));

const ALLOWED_KEYS = ["your-secret-key"];
app.use((req,res,next)=>{
  const key = req.headers["x-api-key"];
  if (!ALLOWED_KEYS.includes(key)) return res.status(403).send("Forbidden");
  next();
});

const HOMELAB_MANIFEST_URL = process.env.HOMELAB_MANIFEST_URL || "http://100.101.102.103:3000/manifest.json";

app.get("/", async (req,res)=>{
  try {
    const r = await fetch(HOMELAB_MANIFEST_URL);
    if (!r.ok) return res.status(502).send("Cannot fetch manifest from homelab");
    const data = await r.text();
    res.setHeader("Content-Type","application/json");
    res.send(data);
  } catch (e) {
    console.error(e);
    res.status(500).send("Error fetching manifest");
  }
});

// Export handler function for Vercel
export default function handler(req, res) {
  return app(req, res);
}
