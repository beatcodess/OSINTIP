import express from "express";
import axios from "axios";
import dns from "dns/promises";
import tls from "tls";

const app = express();
app.use(express.json());
app.use(express.static("public"));

const torExit = new Set();

(async () => {
  try {
    const { data } = await axios.get(
      "https://check.torproject.org/torbulkexitlist"
    );
    data.split("\n").forEach(ip => ip && torExit.add(ip.trim()));
  } catch {}
})();

async function getTLS(host) {
  return new Promise(resolve => {
    const socket = tls.connect(443, host, { servername: host }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      resolve(cert);
    });
    socket.on("error", () => resolve(null));
  });
}

app.post("/api/recon", async (req, res) => {
  try {
    let target = req.body.target;
    let ip = target;

    if (/[a-zA-Z]/.test(target)) {
      ip = (await dns.lookup(target)).address;
    }

    const geo = await axios.get(`https://ipwho.is/${ip}`);
    if (!geo.data.success) throw "Geo lookup failed";

    const geoData = {
      city: geo.data.city,
      region: geo.data.region,
      country: geo.data.country,
      lat: geo.data.latitude,
      lon: geo.data.longitude,
      timezone: geo.data.timezone?.id,
      isp: geo.data.isp,
      asn: geo.data.connection?.asn,
      org: geo.data.connection?.org,
      proxy: geo.data.proxy,
      hosting: geo.data.hosting
    };

    const dnsInfo = {};
    try { dnsInfo.A = await dns.resolve(target); } catch {}
    try { dnsInfo.MX = await dns.resolveMx(target); } catch {}
    try { dnsInfo.NS = await dns.resolveNs(target); } catch {}
    try { dnsInfo.TXT = await dns.resolveTxt(target); } catch {}

    let headers = {};
    try {
      const r = await axios.get(`https://${target}`, { timeout: 4000 });
      headers = r.headers;
    } catch {}

    const cert = await getTLS(target);

    let cloud = "Unknown";
    if (geoData.org?.match(/cloudflare/i)) cloud = "Cloudflare";
    if (geoData.org?.match(/amazon|aws/i)) cloud = "AWS";
    if (geoData.org?.match(/google/i)) cloud = "Google";
    if (geoData.org?.match(/azure|microsoft/i)) cloud = "Azure";
    if (geoData.org?.match(/digitalocean/i)) cloud = "DigitalOcean";
    if (geoData.org?.match(/ovh/i)) cloud = "OVH";

    let score = 100;
    if (geoData.proxy) score -= 25;
    if (geoData.hosting) score -= 20;
    if (torExit.has(ip)) score -= 40;
    if (cloud !== "Unknown") score -= 10;

    res.json({
      target,
      ip,
      geo: geoData,
      cloud,
      privacy: {
        vpn: geoData.proxy ? "Likely" : "No",
        tor: torExit.has(ip) ? "Yes" : "No",
        hosting: geoData.hosting ? "Yes" : "No"
      },
      dns: dnsInfo,
      http_headers: headers,
      tls: cert ? {
        issuer: cert.issuer?.O,
        valid_from: cert.valid_from,
        valid_to: cert.valid_to,
        wildcard: cert.subject?.CN?.startsWith("*")
      } : null,
      services: {
        web: headers.server ? "Yes" : "Unknown",
        mail: dnsInfo.MX ? "Yes" : "Unknown",
        cdn: cloud !== "Unknown" ? "Likely" : "No"
      },
      open_ports_probability: cloud !== "Unknown"
        ? ["80", "443", "22"]
        : ["80", "443"],
      confidence: Math.max(score, 0),
      honeypot_risk:
        score < 40 ? "High" : score < 70 ? "Medium" : "Low",
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("Server running on", PORT));
