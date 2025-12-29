const express = require("express");
const axios = require("axios");
const dns = require("dns").promises;

const app = express();
app.use(express.json());
app.use(express.static("public"));

const isIP = v => /^[0-9.]+$/.test(v);

let torSet = new Set();
let torLast = 0;

async function updateTor() {
  if (Date.now() - torLast < 6 * 60 * 60 * 1000) return;
  try {
    const r = await axios.get("https://check.torproject.org/torbulkexitlist");
    torSet = new Set(
      r.data.split("\n").filter(l => l && !l.startsWith("#"))
    );
    torLast = Date.now();
  } catch {}
}

async function geo(ip) {
  try {
    const r = await axios.get(`https://ipwho.is/${ip}`);
    if (r.data?.success) return r.data;
  } catch {}
  return null;
}

app.post("/api/recon", async (req, res) => {
  const input = req.body.target?.trim();
  if (!input) return res.json({ error: "Enter IP or domain" });

  try {
    await updateTor();

    let ip = input;
    let dnsData = null;

    if (!isIP(input)) {
      const r = await dns.lookup(input);
      ip = r.address;
      dnsData = {
        A: await dns.resolve(input, "A").catch(() => []),
        MX: await dns.resolveMx(input).catch(() => []),
        NS: await dns.resolveNs(input).catch(() => [])
      };
    }

    const g = await geo(ip);

    res.json({
      input,
      ip,
      type: isIP(input) ? "ip" : "domain",
      tor: torSet.has(ip),
      vpn_likelihood: g?.proxy || g?.hosting ? "High" : "Low",
      geo: g ? {
        city: g.city,
        region: g.region,
        country: g.country,
        lat: g.latitude,
        lon: g.longitude,
        isp: g.isp
      } : null,
      dns: dnsData,
      time: new Date().toISOString()
    });
  } catch {
    res.json({ error: "Lookup failed" });
  }
});

app.listen(process.env.PORT || 10000);
