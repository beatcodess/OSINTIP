import express from "express";
import axios from "axios";
import dns from "dns/promises";

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

const ipinfo = async ip =>
  (await axios.get(`https://ipinfo.io/${ip}/json`)).data;

const ipapi = async ip =>
  (await axios.get(`https://ipapi.co/${ip}/json/`)).data;

const cloudDetect = org => {
  const s = org?.toLowerCase() || "";
  if (s.includes("amazon")) return "AWS";
  if (s.includes("google")) return "GCP";
  if (s.includes("microsoft")) return "Azure";
  if (s.includes("cloudflare")) return "Cloudflare";
  if (s.includes("akamai")) return "Akamai";
  return "Unknown";
};

const confidence = (a, b) => {
  let score = 0;
  if (a.city === b.city) score += 30;
  if (a.region === b.region) score += 30;
  if (a.country === b.country_name) score += 40;
  return `${score}%`;
};

app.post("/api/recon", async (req, res) => {
  try {
    const target = req.body.target;
    const ip = await resolveIP(target);
    const [i1, i2] = await Promise.all([ipinfo(ip), ipapi(ip)]);
    const ptr = await reverseDNS(ip);

    res.json({
      target,
      ip,
      hostname: i1.hostname || ptr,
      isp: i1.org,
      asn: i1.org?.split(" ")[0],
      city: i1.city,
      region: i1.region,
      country: i1.country,
      location: i1.loc,
      timezone: i1.timezone,
      cloud: cloudDetect(i1.org),
      confidence: confidence(i1, i2),
      timestamp: new Date().toISOString()
    });
  } catch {
    res.status(500).json({ error: "Recon failed" });
  }
});

app.listen(3000, () =>
  console.log("Recon UI running on http://localhost:3000")
);
