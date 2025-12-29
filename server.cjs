const express = require("express");
const axios = require("axios");
const dns = require("dns").promises;

const app = express();
app.use(express.json());
app.use(express.static("public"));

const isIP = (v) => /^[0-9.]+$/.test(v);

let torExitSet = new Set();
let lastTorFetch = 0;

async function updateTorList() {
  if (Date.now() - lastTorFetch < 6 * 60 * 60 * 1000) return;
  try {
    const r = await axios.get("https://check.torproject.org/torbulkexitlist", {
      timeout: 8000
    });
    torExitSet = new Set(
      r.data
        .split("\n")
        .map(l => l.trim())
        .filter(l => l && !l.startsWith("#"))
    );
    lastTorFetch = Date.now();
  } catch {}
}

async function geoLookup(ip) {
  try {
    const r = await axios.get(`https://ipwho.is/${ip}`, { timeout: 8000 });
    if (r.data?.success) {
      return {
        ip,
        city: r.data.city || null,
        region: r.data.region || null,
        country: r.data.country || null,
        lat: r.data.latitude || null,
        lon: r.data.longitude || null,
        isp: r.data.isp || null,
        org: r.data.connection?.org || null,
        asn: r.data.connection?.asn || null,
        hosting: !!r.data.hosting,
        proxy: !!r.data.proxy
      };
    }
  } catch {}

  try {
    const r = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout: 8000 });
    return {
      ip,
      city: r.data.city || null,
      region: r.data.region || null,
      country: r.data.country_name || null,
      lat: r.data.latitude || null,
      lon: r.data.longitude || null,
      isp: r.data.org || null,
      org: r.data.org || null,
      asn: r.data.asn || null,
      hosting: false,
      proxy: false
    };
  } catch {}

  return null;
}

function vpnLikelihood(geo) {
  if (!geo) return "Unknown";
  if (geo.proxy) return "High";
  if (geo.hosting) return "High";
  if (geo.org && /amazon|google|microsoft|ovh|digitalocean|hetzner|linode/i.test(geo.org))
    return "High";
  return "Low";
}

app.post("/api/recon", async (req, res) => {
  const target = req.body.target?.trim();
  if (!target) return res.json({ error: "Enter IP or domain" });

  try {
    await updateTorList();

    let ip = target;
    let dnsData = null;

    if (!isIP(target)) {
      const resolved = await dns.lookup(target);
      ip = resolved.address;

      dnsData = {
        A: await dns.resolve(target, "A").catch(() => []),
        AAAA: await dns.resolve(target, "AAAA").catch(() => []),
        MX: await dns.resolveMx(target).catch(() => []),
        NS: await dns.resolveNs(target).catch(() => []),
        TXT: await dns.resolveTxt(target).catch(() => [])
      };
    }

    const geo = await geoLookup(ip);
    const tor = torExitSet.has(ip);
    const vpn = vpnLikelihood(geo);

    res.json({
      input: target,
      type: isIP(target) ? "ip" : "domain",
      ip,
      tor,
      vpn_likelihood: vpn,
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
