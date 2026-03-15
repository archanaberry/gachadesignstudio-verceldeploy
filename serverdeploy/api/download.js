// serverdeploy/api/download.js
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

const app = express();
app.use(helmet());
app.use(express.json());

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    standardHeaders: true,
    legacyHeaders: false,
    message: "Too many downloads, try again later.",
  })
);

const API_KEYS = (process.env.ALLOWED_KEYS || "your-secret-key").split(",");

app.use((req, res, next) => {
  const key = req.headers["x-api-key"] || req.query.api_key;
  if (!API_KEYS.includes(key)) return res.status(403).send("Forbidden");
  next();
});

const HOMELAB_DOWNLOAD_BASE =
  process.env.HOMELAB_DOWNLOAD_URL || "http://100.101.102.103:3000/download";

app.get("/:filename", async (req, res) => {
  const filename = req.params.filename;
  try {
    const url = `${HOMELAB_DOWNLOAD_BASE}/${encodeURIComponent(filename)}`;
    const r = await fetch(url);
    if (r.status === 404) return res.status(404).send("File not found");
    if (!r.ok) return res.status(502).send("Error fetching file from homelab");

    // stream the response
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename}"`
    );
    const reader = r.body.getReader();
    const encoder = new TextEncoder();
    const stream = new WritableStream({
      write(chunk) {
        // no-op (we'll pipe via iteration)
      }
    });

    // simpler: just pipe via arrayBuffer for now (Vercel memory limits apply)
    const buf = Buffer.from(await r.arrayBuffer());
    res.setHeader("Content-Length", buf.length);
    res.status(200).send(buf);
  } catch (err) {
    console.error("download error:", err);
    res.status(500).send("Error downloading file");
  }
});

export default function handler(req, res) {
  return app(req, res);
}
