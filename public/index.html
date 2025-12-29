<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>RECON</title>

<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

<style>
body {
  margin: 0;
  font-family: monospace;
  color: white;
  background: url("https://files.catbox.moe/sm4udj.png") center/contain no-repeat fixed black;
}

body::before {
  content: "";
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.65);
  backdrop-filter: blur(3px);
  z-index: -1;
}

header {
  position: fixed;
  top: 15px;
  right: 20px;
  font-size: 18px;
  cursor: pointer;
  text-shadow: 0 0 12px white;
}

.container {
  max-width: 520px;
  margin: 90px auto;
  padding: 20px;
  background: rgba(0,0,0,0.6);
  backdrop-filter: blur(10px);
  border-radius: 15px;
  box-shadow: 0 0 20px rgba(255,255,255,0.4);
  text-align: center;
}

input, button {
  width: 80%;
  max-width: 300px;
  padding: 8px;
  margin: 8px auto;
  display: block;
  background: rgba(0,0,0,0.8);
  color: white;
  border: 1px solid white;
  box-shadow: 0 0 8px rgba(255,255,255,0.3);
}

pre {
  text-align: left;
  font-size: 13px;
  margin-top: 15px;
  white-space: pre-wrap;
  text-shadow: 0 0 4px white;
}

#map {
  height: 260px;
  margin-top: 15px;
  border-radius: 10px;
  display: none;
}
</style>
</head>

<body>

<header onclick="window.open('https://guns.lol/beatcodes','_blank')">
  <span id="name"></span> ✔
</header>

<div class="container">
  <h2>RECON</h2>
  <input id="target" placeholder="Enter IP or Domain">
  <button onclick="run()">Run Recon</button>
  <pre id="out"></pre>
  <div id="map"></div>
</div>

<audio id="bgm" loop></audio>

<script>
const nameText = "beatcodes";
let i = 0;
setInterval(() => {
  i = (i + 1) % (nameText.length + 1);
  document.getElementById("name").textContent = nameText.slice(0, i);
}, 200);

const bgm = document.getElementById("bgm");
bgm.src = "https://files.catbox.moe/87e8gv.mp3";
document.addEventListener("click", () => bgm.play(), { once: true });

let map, circle;

async function run() {
  const t = document.getElementById("target").value.trim();
  const out = document.getElementById("out");
  const mapDiv = document.getElementById("map");

  if (!t) {
    out.textContent = "Enter something";
    mapDiv.style.display = "none";
    return;
  }

  out.textContent = "Running recon...";
  mapDiv.style.display = "none";

  const r = await fetch("/api/recon", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target: t })
  });

  const data = await r.json();
  if (data.error) {
    out.textContent = data.error;
    return;
  }

  let text = `
Input    : ${data.input}
Type     : ${data.type}

City     : ${data.geo.city}
Region   : ${data.geo.region}
Country  : ${data.geo.country}
ISP      : ${data.geo.isp}
ASN      : ${data.geo.asn}

VPN      : ${data.geo.vpn}
Hosting  : ${data.geo.hosting}
`;

  if (data.type === "domain") {
    text += `

DNS:
A     : ${data.dns.A.join(", ")}
AAAA  : ${data.dns.AAAA.join(", ")}
MX    : ${data.dns.MX.map(x => x.exchange).join(", ")}
NS    : ${data.dns.NS.join(", ")}
TXT   : ${data.dns.TXT.flat().join(", ")}
`;
  }

  out.textContent = text.trim();

  const lat = data.geo.latitude;
  const lon = data.geo.longitude;

  if (lat && lon) {
    mapDiv.style.display = "block";

    if (!map) {
      map = L.map("map").setView([lat, lon], 6);
      L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png").addTo(map);
    } else {
      map.setView([lat, lon], 6);
      if (circle) circle.remove();
    }

    circle = L.circle([lat, lon], {
      radius: 50000,
      color: "white",
      fillOpacity: 0.2
    }).addTo(map);
  }
}
</script>

</body>
</html>
