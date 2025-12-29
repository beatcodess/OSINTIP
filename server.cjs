const express = require("express");
const axios = require("axios");
const dns = require("dns").promises;

const app = express();
app.use(express.json());
app.use(express.static("public"));

const isIP = (v) => /^[0-9.]+$/.test(v);

async function geoLookup(ip) {
  try {
    const r = await axios.get(`https://ipwho.is/${ip}`);
    if (r.data && r.data.success) {
      return {
        ip,
        city: r.data.city || null,
        region: r.data.region || null,
        country: r.data.country || null,
        latitude: r.data.latitude || null,
        longitude: r.data.longitude || null,
        isp: r.data.isp || null,
        asn: r.data.connection?.asn || null,
        org: r.data.connection?.org || null,
        vpn: !!r.data.proxy,
        hosting: !!r.data.hosting
      };
    }
  } catch {}

  try {
    const r = await axios.get(`https://ipapi.co/${ip}/json/`);
    return {
      ip,
      city: r.data.city || null,
      region: r.data.region || null,
      country: r.data.country_name || null,
      latitude: r.data.latitude || null,
      longitude: r.data.longitude || null,
      isp: r.data.org || null,
      asn: r.data.asn || null,
      org: r.data.org || null,
      vpn: false,
      hosting: false
    };
  } catch {}

  return {
    ip,
    city: null,
    region: null,
    country: null,
    latitude: null,
    longitude: null,
    isp: null,
    asn: null,
    org: null,
    vpn: null,
    hosting: null
  };
}

app.post("/api/recon", async (req, res) => {
  const target = req.body.target?.trim();
  if (!target) return res.json({ error: "Enter IP or domain" });

  try {
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

    res.json({
      input: target,
      type: isIP(target) ? "ip" : "domain",
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
