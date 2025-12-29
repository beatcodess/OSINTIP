import express from "express";
import fetch from "node-fetch";
import dns from "dns/promises";

const app = express();

app.use(express.json());
app.use(express.static("public"));

app.post("/api/recon", async (req, res) => {
  try {
    const target = req.body.target;
    if (!target) throw "No target provided";

    let ip = target;
    if (/[a-zA-Z]/.test(target)) {
      const lookup = await dns.lookup(target);
      ip = lookup.address;
    }

    const r = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,as,proxy,hosting`
    );

    const j = await r.json();
    if (j.status !== "success") throw j.message;

    res.json({
      target,
      ip,
      geo: {
        city: j.city,
        region: j.regionName,
        country: j.country,
        country_code: j.countryCode,
        lat: j.lat,
        lon: j.lon,
        timezone: j.timezone
      },
      isp: j.isp,
      asn: j.as,
      privacy: {
        vpn: j.proxy ? "Possible" : "No",
        tor: j.hosting ? "Possible" : "No",
        proxy: j.proxy ? "Yes" : "No",
        hosting: j.hosting ? "Yes" : "No"
      },
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.json({ error: String(e) });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
