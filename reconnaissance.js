#!/usr/bin/env node

import axios from "axios";
import dns from "dns/promises";

const target = process.argv[2];

if (!target) {
  console.log("\nUsage: node recon.js <IP | Hostname>\n");
  process.exit(1);
}

const pad = (label, value) =>
  `${label.padEnd(15)} : ${value ?? "N/A"}`;

async function resolveTarget(input) {
  try {
    const { address } = await dns.lookup(input);
    return address;
  } catch {
    return input;
  }
}

async function lookupIP(ip) {
  const { data } = await axios.get(`https://ipinfo.io/${ip}/json`);
  return data;
}

(async () => {
  try {
    const ip = await resolveTarget(target);
    const data = await lookupIP(ip);

    console.log("\n══════════════ Recon Results ══════════════\n");

    console.log(pad("Target", target));
    console.log(pad("IP Address", data.ip));
    console.log(pad("Hostname", data.hostname));
    console.log(pad("ISP / ASN", data.org));
    console.log(pad("City", data.city));
    console.log(pad("Region", data.region));
    console.log(pad("Country", data.country));
    console.log(pad("Postal", data.postal));
    console.log(pad("Coordinates", data.loc));
    console.log(pad("Timezone", data.timezone));

    console.log("\n═══════════════════════════════════════════\n");

  } catch (err) {
    console.error("\nError:", err.message, "\n");
  }
})();
