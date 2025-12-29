import express from "express";
import axios from "axios";
import dns from "dns/promises";

const app = express();
app.use(express.json());
app.use(express.static("public"));

const isIP = (v) => /^[0-9.]+$/.test(v);

async function geoLookup(ip) {
  const r = await axios.get(`https://ipwho.is/${ip}`);
  if (!r.data.success) throw new Error("geo fail");

  return {
    ip,
    city: r.data.city,
    region: r.data.region,
    country: r.data.country,
    latitude: r.data.latitude,
    longitude: r.data.longitude,
    isp: r.data.isp,
    asn: r.data.connection?.asn,
    org: r.data.connection?.org,
    vpn: r.data.proxy,
    hosting: r.data.hosting
  };
}

app.post("/api/recon", async (req, res) => {
  const target = req.body.target?.trim();
  if (!target) return res.json({ error: "Enter something" });

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
