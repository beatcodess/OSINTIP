import express from "express";
import axios from "axios";
import dns from "dns/promises";
import https from "https";

const app = express();
app.use(express.json());
app.use(express.static("public"));

const resolveIP = async t => {
  try {
    return (await dns.lookup(t)).address;
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
  const d = {};
  try { d.A = await dns.resolve4(host); } catch { d.A = []; }
  try { d.AAAA = await dns.resolve6(host); } catch { d.AAAA = []; }
  try { d.MX = await dns.resolveMx(host); } catch { d.MX = []; }
  try { d.NS = await dns.resolveNs(host); } catch { d.NS = []; }
  try {
    const txt = (await dns.resolveTxt(host)).flat();
    d.TXT = txt;
    d.SPF = txt.some(v => v.includes("v=spf"));
    d.DMARC = txt.some(v => v.toLowerCase().includes("dmarc"));
  } catch {
    d.TXT = [];
    d.SPF = false;
    d.DMARC = false;
  }
  try {
    d.DNSSEC = (await dns.resolveDs(host)).length > 0;
  } catch {
    d.DNSSEC = false;
  }
  return d;
};

const checkHTTP = ip =>
  new Promise(resolve => {
    const r = https.get(
      { host: ip, timeout: 3000, rejectUnauthorized: false },
      () => resolve(true)
    );
    r.on("error", () => resolve(false));
    r.on("timeout", () => {
      r.destroy();
      resolve(false);
    });
  });

const honeypotAnalysis = data => {
  let score = 0;
  let reasons = [];

  const org = (data.isp || "").toLowerCase();
  const host = (data.hostname || "").toLowerCase();

  if (org.includes("amazon") || org.includes("google") || org.includes("microsoft")) {
    score += 20;
    reasons.push("Cloud infrastructure");
  }

  if (host.includes("static") || host.includes("compute") || host.includes("scan")) {
    score += 20;
    reasons.push("Generic PTR hostname");
  }

  if (!data.http) {
    score += 30;
    reasons.push("No HTTP/S response");
  }

  if (!data.city) {
    score += 10;
    reasons.push("Missing geolocation detail");
  }

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

    const [ipinfo, ptr, http, dnsdata] = await Promise.all([
      axios.get(`https://ipinfo.io/${ip}/json`).then(r => r.data),
      reverseDNS(ip),
      checkHTTP(ip),
      dnsIntel(target)
    ]);

    const honeypot = honeypotAnalysis({
      isp: ipinfo.org,
      hostname: ipinfo.hostname || ptr,
      city: ipinfo.city,
      http
    });

    res.json({
      target,
      ip,
      hostname: ipinfo.hostname || ptr,
      isp: ipinfo.org,
      city: ipinfo.city,
      region: ipinfo.region,
      country: ipinfo.country,
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
