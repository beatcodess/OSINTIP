import express from "express";
import axios from "axios";
import dns from "dns/promises";

const app = express();
app.use(express.json());
app.use(express.static("public"));

async function safe(fn, fallback = null) {
  try { return await fn(); } catch { return fallback; }
}

async function geoLookup(ip) {
  const who = await safe(() => axios.get(`https://ipwho.is/${ip}`));
  if (who?.data?.success) {
    return {
      city: who.data.city || null,
      region: who.data.region || null,
      country: who.data.country || null,
      lat: who.data.latitude || null,
      lon: who.data.longitude || null,
      isp: who.data.isp || null,
      org: who.data.connection?.org || null,
      asn: who.data.connection?.asn || null,
      proxy: !!who.data.proxy,
      hosting: !!who.data.hosting
    };
  }

  const info = await safe(() => axios.get(`https://ipinfo.io/${ip}/json`));
  if (info?.data) {
    return {
      city: info.data.city || null,
      region: info.data.region || null,
      country: info.data.country || null,
      lat: info.data.loc?.split(",")[0] || null,
      lon: info.data.loc?.split(",")[1] || null,
      isp: info.data.org || null,
      org: info.data.org || null,
      asn: info.data.org || null,
      proxy: false,
      hosting: false
    };
  }

  return {};
}

app.post("/api/recon", async (req, res) => {
  const result = {
    target: req.body.target || null,
    ip: null,
    geo: {},
    dns: {},
    services: {},
    confidence: 0,
    timestamp: new Date().toISOString()
  };

  try {
    if (!result.target) return res.json(result);

    result.ip = /[a-zA-Z]/.test(result.target)
      ? (await dns.lookup(result.target)).address
      : result.target;

    result.geo = await geoLookup(result.ip);

    result.dns.A = await safe(() => dns.resolve(result.target));
    result.dns.MX = await safe(() => dns.resolveMx(result.target));
    result.dns.NS = await safe(() => dns.resolveNs(result.target));

    result.services.web = result.dns.A ? "Likely" : "Unknown";
    result.services.mail = result.dns.MX ? "Likely" : "Unknown";

    let score = 100;
    if (result.geo.proxy) score -= 25;
    if (result.geo.hosting) score -= 20;
    result.confidence = Math.max(score, 0);

    return res.json(result);
  } catch {
    return res.json(result);
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("Server running on", PORT));
