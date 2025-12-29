import express from "express";
import axios from "axios";
import dns from "dns/promises";

const app = express();
app.use(express.json());
app.use(express.static("public"));

const rate = new Map();

app.use((req, res, next) => {
  const ip = req.ip;
  const now = Date.now();
  if (!rate.has(ip)) rate.set(ip, []);
  rate.set(ip, rate.get(ip).filter(t => now - t < 60000));
  if (rate.get(ip).length > 30)
    return res.status(429).json({ error: "Rate limit exceeded" });
  rate.get(ip).push(now);
  next();
});

app.use((req, res, next) => {
  res.setHeader("X-Robots-Tag", "noindex");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  next();
});

let torExit = new Set();
(async () => {
  try {
    const { data } = await axios.get(
      "https://check.torproject.org/torbulkexitlist"
    );
    data.split("\n").forEach(ip => torExit.add(ip.trim()));
  } catch {}
})();

app.post("/api/recon", async (req, res) => {
  try {
    const target = req.body.target;
    let ip = target;

    if (/[a-zA-Z]/.test(target)) {
      ip = (await dns.lookup(target)).address;
    }

    const { data } = await axios.get(
      `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,as,proxy,hosting`
    );

    if (data.status !== "success") throw data.message;

    let score = 100;
    if (data.proxy) score -= 25;
    if (data.hosting) score -= 20;
    if (torExit.has(ip)) score -= 40;

    res.json({
      target,
      ip,
      geo: {
        city: data.city,
        region: data.regionName,
        country: data.country,
        code: data.countryCode,
        lat: data.lat,
        lon: data.lon,
        timezone: data.timezone
      },
      isp: data.isp,
      asn: data.as,
      privacy: {
        vpn: data.proxy ? "Likely" : "No",
        tor: torExit.has(ip) ? "Yes" : "No",
        hosting: data.hosting ? "Yes" : "No"
      },
      confidence: Math.max(score, 0),
      honeypot: score < 40 ? "High risk" : score < 70 ? "Medium risk" : "Low risk",
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("Server running on", PORT));
