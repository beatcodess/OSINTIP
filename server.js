import express from "express";
import axios from "axios";
import dns from "dns/promises";
import https from "https";
import tls from "tls";

const app = express();
app.use(express.json());
app.use(express.static("public"));

const resolveIP = async t => {
  try { return (await dns.lookup(t)).address; } catch { return t; }
};

const reverseDNS = async ip => {
  try { return (await dns.reverse(ip)).join(", "); } catch { return null; }
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
  try { d.DNSSEC = (await dns.resolveDs(host)).length > 0; }
  catch { d.DNSSEC = false; }
  return d;
};

const checkHTTP = ip =>
  new Promise(r => {
    const q = https.get({ host: ip, timeout: 3000, rejectUnauthorized: false }, () => r(true));
    q.on("error", () => r(false));
    q.on("timeout", () => { q.destroy(); r(false); });
  });

const tlsIntel = host =>
  new Promise(resolve => {
    const s = tls.connect(443, host, { servername: host, timeout: 3000 }, () => {
      const c = s.getPeerCertificate();
      resolve({
        tls: s.getProtocol(),
        issuer: c.issuer?.O || "Unknown",
        valid_to: c.valid_to || "Unknown",
        self_signed: c.issuer?.O === c.subject?.O
      });
      s.end();
    });
    s.on("error", () => resolve(null));
    s.on("timeout", () => resolve(null));
  });

const honeypot = d => {
  let score = 0;
  let reasons = [];
  const org = (d.isp || "").toLowerCase();
  const host = (d.hostname || "").toLowerCase();

  if (org.includes("amazon") || org.includes("google") || org.includes("microsoft"))
    score += 20, reasons.push("Cloud infrastructure");

  if (host.includes("static") || host.includes("compute") || host.includes("scan"))
    score += 20, reasons.push("Generic PTR hostname");

  if (!d.http)
    score += 30, reasons.push("No HTTP/S service");

  if (!d.city)
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

    const [ipinfo, ptr, http, dnsdata, tlsdata] = await Promise.all([
      axios.get(`https://ipinfo.io/${ip}/json`).then(r => r.data),
      reverseDNS(ip),
      checkHTTP(ip),
      dnsIntel(target),
      tlsIntel(target)
    ]);

    const h = honeypot({
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
      tls: tlsdata,
      dns: dnsdata,
      honeypot: h,
      timestamp: new Date().toISOString()
    });
  } catch {
    res.status(500).json({ error: "Recon failed" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
