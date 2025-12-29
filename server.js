import express from "express";
import axios from "axios";
import dns from "dns/promises";
import https from "https";

const app = express();
app.use(express.json());
app.use(express.static("public"));

const resolveIP = async t => {
  try {
    const r = await dns.lookup(t);
    return r.address;
  } catch {
    return t;
  }
};

const reverseDNS = async ip => {
  try {
    return (await dns.reverse(ip)).join(", ");
  } catch {
    return null;
  }
};

const dnsIntel = async host => {
  const out = {};
  try { out.A = (await dns.resolve4(host)); } catch { out.A = []; }
  try { out.AAAA = (await dns.resolve6(host)); } catch { out.AAAA = []; }
  try { out.MX = (await dns.resolveMx(host)); } catch { out.MX = []; }
  try { out.NS = (await dns.resolveNs(host)); } catch { out.NS = []; }
  try {
    const txt = await dns.resolveTxt(host);
    out.TXT = txt.flat();
    out.SPF = out.TXT.some(v => v.includes("v=spf"));
    out.DMARC = out.TXT.some(v => v.includes("dmarc"));
  } catch {
    out.TXT = [];
    out.SPF = false;
    out.DMARC = false;
  }
  try {
    const ds = await dns.resolveDs(host);
    out.DNSSEC = ds.length > 0;
  } catch {
    out.DNSSEC = false;
  }
  return out;
};

const checkHTTP = ip =>
  new Promise(resolve => {
    const req = https.get(
      { host: ip, timeout: 3000, rejectUnauthorized: false },
      () => resolve(true)
    );
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
  });

const honeypotScore = data => {
  let score = 0;
  let reasons = [];
  const org = (data.isp || "").toLowerCase();
  const host = (data.hostname || "").toLowerCase();

  if (org.includes("amazon") || org.includes("google") || org.includes("microsoft"))
    score += 20, reasons.push("Cloud infrastructure");

  if (host.includes("static") || host.includes("compute") || host.includes("scan"))
    score += 20, reasons.push("Generic PTR hostname");

  if (!data.http)
    score += 30, reasons.push("No HTTP/S response");

  if (!data.city)
    score += 10, reasons.push("Missing geolocation");

  const verdict =
    score >= 60 ? "Likely Honeypot" :
    score >= 35 ? "Suspicious" :
    "Likely Active Service";

  return { score: `${score}%`, verdict, reasons };
};

app.post("/api/recon", async (req, res) => {
  try {
    const target = req.body.target;
    const ip = await resolveIP(target);

    const [i1, ptr, http, dnsdata] = await Promise.all([
      axios.get(`https://ipinfo.io/${ip}/json`).then(r => r.data),
      reverseDNS(ip),
      checkHTTP(ip),
      dnsIntel(target)
    ]);

    const honeypot = honeypotScore({
      isp: i1.org,
      hostname: i1.hostname || ptr,
      city: i1.city,
      http
    });

    res.json({
      target,
      ip,
      hostname: i1.hostname || ptr,
      isp: i1.org,
      city: i1.city,
      region: i1.region,
      country: i1.country,
      http,
      dns: dnsdata,
      honeypot,
      timestamp: new Date().toISOString()
    });
  } catch {
    res.status(500).json({ error: "Recon failed" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
