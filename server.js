import express from "express";
import axios from "axios";
import dns from "dns/promises";

const app = express();
app.use(express.json());
app.use(express.static("public"));

const isIP = (t) => /^[0-9.]+$/.test(t);

async function geo(ip) {
  const r = await axios.get(`https://ipwho.is/${ip}`);
  if (!r.data.success) throw new Error("geo fail");
  return {
    ip,
    city: r.data.city,
    region: r.data.region,
    country: r.data.country,
    lat: r.data.latitude,
    lon: r.data.longitude,
    isp: r.data.isp,
    org: r.data.connection?.org,
    asn: r.data.connection?.asn,
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

    const geoData = await geo(ip);

    res.json({
      input: target,
      type: isIP(target) ? "ip" : "domain",
      geo: geoData,
      dns: dnsData,
      timestamp: new Date().toISOString()
    });
  } catch {
    res.json({ error: "Lookup failed" });
  }
});

app.listen(10000, () => console.log("Server running"));
