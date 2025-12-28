#!/usr/bin/env node

import axios from "axios";
import dns from "dns/promises";
import fs from "fs";
import crypto from "crypto";
import path from "path";

const input = process.argv[2];
const flags = process.argv.slice(3);

if (!input) {
  console.log("\nUsage: node recon.js <IP | Host | file.txt> [--json] [--file]\n");
  process.exit(1);
}

const isJSON = flags.includes("--json");
const saveFile = flags.includes("--file");

const pad = (k, v) => `${k.padEnd(22)} : ${v ?? "N/A"}`;

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

const dnsRecords = async host => {
  try {
    const [a, mx, ns, txt] = await Promise.allSettled([
      dns.resolve(host),
      dns.resolveMx(host),
      dns.resolveNs(host),
      dns.resolveTxt(host)
    ]);
    return {
      A: a.value,
      MX: mx.value?.map(x => x.exchange),
      NS: ns.value,
      TXT: txt.value?.flat()
    };
  } catch {
    return {};
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

const hashData = d =>
  crypto.createHash("sha256").update(d).digest("hex");

const processTarget = async target => {
  const ip = await resolveIP(target);
  const [i1, i2] = await Promise.all([ipinfo(ip), ipapi(ip)]);
  const ptr = await reverseDNS(ip);
  const dnsInfo = target.includes(".") ? await dnsRecords(target) : null;

  return {
    target,
    ip,
    hostname: i1.hostname || ptr,
    city: i1.city,
    region: i1.region,
    country: i1.country,
    isp: i1.org,
    asn: i1.org?.split(" ")[0],
    netblock: i1.ip,
    timezone: i1.timezone,
    location: i1.loc,
    cloud: cloudDetect(i1.org),
    dns: dnsInfo,
    confidence: confidence(i1, i2),
    timestamp: new Date().toISOString()
  };
};

const targets = fs.existsSync(input)
  ? fs.readFileSync(input, "utf-8").split("\n").filter(Boolean)
  : [input];

const results = [];

for (const t of targets) {
  results.push(await processTarget(t));
}

if (isJSON) {
  const out = JSON.stringify(results, null, 2);
  console.log(out);
  if (saveFile) {
    fs.writeFileSync("recon.json", out);
    fs.writeFileSync("recon.hash", hashData(out));
  }
  process.exit(0);
}

for (const r of results) {
  console.log("\n══════════════ Recon Results ══════════════\n");
  console.log(pad("Target", r.target));
  console.log(pad("IP Address", r.ip));
  console.log(pad("Hostname", r.hostname));
  console.log(pad("ISP / ASN", r.isp));
  console.log(pad("Cloud Provider", r.cloud));
  console.log(pad("City", r.city));
  console.log(pad("Region", r.region));
  console.log(pad("Country", r.country));
  console.log(pad("Coordinates", r.location));
  console.log(pad("Timezone", r.timezone));
  console.log(pad("Geo Confidence", r.confidence));
  console.log(pad("Timestamp (UTC)", r.timestamp));

  if (r.dns) {
    console.log("\nDNS Records");
    Object.entries(r.dns).forEach(([k, v]) =>
      console.log(pad(k, v?.join(", ")))
    );
  }

  console.log("\n═══════════════════════════════════════════\n");
}

if (saveFile) {
  const out = JSON.stringify(results, null, 2);
  fs.writeFileSync("recon.json", out);
  fs.writeFileSync("recon.hash", hashData(out));
}
