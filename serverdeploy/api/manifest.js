import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import fetch from "node-fetch";

const app = express();
app.use(helmet());

// Rate limit + API key check
app.use(rateLimit({
  windowMs: 15*60*1000,
  max: 100,
  message: "Too many requests, try again later"
}));

const ALLOWED_KEYS = ["your-secret-key"];
app.use((req,res,next)=>{
  const key = req.headers["x-api-key"];
  if(!ALLOWED_KEYS.includes(key)) return res.status(403).send("Forbidden");
  next();
});

// Proxy manifest.json dari homedeploy
const HOMELAB_MANIFEST_URL = "http://100.101.102.103:3000/manifest.json"; // IP Tailscale/WireGuard

app.get("/", async (req,res)=>{
  try{
    const r = await fetch(HOMELAB_MANIFEST_URL);
    if(!r.ok) return res.status(500).send("Cannot fetch manifest");
    const data = await r.text();
    res.setHeader("Content-Type","application/json");
    res.send(data);
  }catch(e){
    res.status(500).send("Error fetching manifest");
  }
});

export default app;
