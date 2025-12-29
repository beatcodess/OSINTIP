const express = require("express");
const axios = require("axios");
const dns = require("dns").promises;

const app = express();
app.use(express.json());
app.use(express.static("public"));

const isIP = v => /^[0-9.]+$/.test(v);

/* -------- TOR EXIT LIST -------- */
let torSet = new Set();
let torLast = 0;

async function updateTor() {
  if (Date.now() - torLast < 6 * 60 * 60 * 1000) return;
  try {
    const r = await axios.get("https://check.torproject.org/torbulkexitlist", { timeout: 8000 });
    torSet = new Set(
      r.data.split("\n").filter(l => l && !l.startsWith("#"))
    );
    torLast = Date.now();
  } catch {}
}

/* -------- GEO LOOKUP (MULTI PROVIDER) -------- */
async function geoLookup(ip) {
  try {
    const r = await axios.get(`https://ipwho.is/${ip}`, { timeout: 8000 });
    if (r.data?.success) {
      return {
        city: r.data.city,
        region: r.data.region,
        country: r.data.country,
        lat: r.data.latitude,
        lon: r.data.longitude,
        isp: r.data.isp,
        org: r.data.connection?.org,
        asn: r.data.connection?.asn,
        proxy: r.data.proxy,
        hosting: r.data.hosting
      };
    }
  } catch {}

  try {
    const r = await axios.get(`http://ip-api.com/json/${ip}`, { timeout: 8000 });
    if (r.data?.status === "success") {
      return {
        city: r.data.city,
        region: r.data.regionName,
        country: r.data.country,
        lat: r.data.lat,
        lon: r.data.lon,
        isp: r.data.isp,
        org: r.data.org,
        asn: r.data.as,
        proxy: false,
        hosting: /hosting|cloud|vps/i.test(r.data.as || "")
      };
    }
  } catch {}

  return null;
}

/* -------- VPN LIKELIHOOD (FIXED) -------- */
function vpnLikelihood(geo) {
  if (!geo) return "Unknown";

  const dc =
    /amazon|aws|google|microsoft|azure|ovh|digitalocean|linode|hetzner|vultr|leaseweb|choopa|m247|contabo|ionos/i;

  if (geo.proxy) return "High";
  if (geo.hosting) return "High";
  if (dc.test(geo.org || "")) return "High";
  if (dc.test(geo.isp || "")) return "High";
  if (dc.test(geo.asn || "")) return "High";

  return "Low";
}

/* -------- API -------- */
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
        AAAA: await dns.resolve(input, "AAAA").catch(() => []),
        MX: await dns.resolveMx(input).catch(() => []),
        NS: await dns.resolveNs(input).catch(() => []),
        TXT: await dns.resolveTxt(input).catch(() => [])
      };
    }

    const geo = await geoLookup(ip);

    res.json({
      input,
      type: isIP(input) ? "ip" : "domain",
      ip,
      tor: torSet.has(ip),
      vpn_likelihood: vpnLikelihood(geo),
      geo,
      dns: dnsData,
      timestamp: new Date().toISOString()
    });
  } catch {
    res.json({ error: "Lookup failed" });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("Server running on", PORT));
