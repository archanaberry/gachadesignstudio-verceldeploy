import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import fetch from "node-fetch";

const app = express();
app.use(helmet());

app.use(rateLimit({
  windowMs: 15*60*1000,
  max: 50,
  message: "Too many downloads, try again later"
}));

const ALLOWED_KEYS = ["your-secret-key"];
app.use((req,res,next)=>{
  const key = req.headers["x-api-key"];
  if(!ALLOWED_KEYS.includes(key)) return res.status(403).send("Forbidden");
  next();
});

const HOMELAB_DOWNLOAD_URL = "http://100.101.102.103:3000/download";

app.get("/:filename", async (req,res)=>{
  const filename = req.params.filename;
  try{
    const r = await fetch(`${HOMELAB_DOWNLOAD_URL}/${filename}`);
    if(!r.ok) return res.status(404).send("File not found");
    const buffer = await r.arrayBuffer();
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(Buffer.from(buffer));
  }catch(e){
    res.status(500).send("Error downloading file");
  }
});

export default app;
