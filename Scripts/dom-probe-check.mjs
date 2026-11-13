// Real-Chromium validation of the Gulp DOM Probe instrumentation (F16 BRW-010, M13b DoD half).
// Loads the SAME dom-probe.js that GulpBrowser embeds, injects it into a real headless Chromium via
// Playwright, and checks it reports the planted DOM XSS on a vulnerable page and nothing on the safe
// twin (the shapes mirror VulnLab /spa and /safe/spa). Run on a host with Node + Playwright + Chromium.
//
//   PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers NODE_PATH=/opt/node-tools/node_modules \
//     node Scripts/dom-probe-check.mjs
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

// Resolve Playwright through require so NODE_PATH (/opt/node-tools/node_modules) is honored.
const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const here = path.dirname(fileURLToPath(import.meta.url));
const probe = fs.readFileSync(path.join(here, "../Packages/GulpKit/Sources/GulpBrowser/dom-probe.js"), "utf8");

// A vulnerable SPA (location.hash -> innerHTML) and its safe twin (textContent).
const vuln =
  `<!doctype html><html><body><div id="out"></div><script>
     document.getElementById("out").innerHTML = decodeURIComponent(location.hash.slice(1));
   </script></body></html>`;
const safe =
  `<!doctype html><html><body><div id="out"></div><script>
     document.getElementById("out").textContent = decodeURIComponent(location.hash.slice(1));
   </script></body></html>`;

const server = http.createServer((req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.end(req.url.startsWith("/safe") ? safe : vuln);
});

async function check(page, url) {
  const reports = [];
  await page.exposeFunction("__gulpReport", (json) => reports.push(JSON.parse(json)));
  await page.addInitScript(probe);
  await page.goto(url, { waitUntil: "load" });
  await page.waitForTimeout(300);
  return reports;
}

async function main() {
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const payload = encodeURIComponent("<img src=x onerror=alert(1)>");
  const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  let ok = true;
  try {
    const ctxA = await browser.newContext();
    const vulnReports = await check(await ctxA.newPage(), `http://127.0.0.1:${port}/spa#${payload}`);
    const sinkHit = vulnReports.some((r) => r.sink.includes("innerHTML") && r.source === "location.hash");
    console.log(`vuln /spa: ${vulnReports.length} report(s) ${sinkHit ? "(innerHTML<-location.hash OK)" : ""}`);
    if (!sinkHit) { console.error("FAIL: DOM XSS not reported on /spa"); ok = false; }

    const ctxB = await browser.newContext();
    const safeReports = await check(await ctxB.newPage(), `http://127.0.0.1:${port}/safe/spa#${payload}`);
    console.log(`safe /safe/spa: ${safeReports.length} report(s)`);
    if (safeReports.length !== 0) { console.error("FAIL: a flow was reported on the safe twin"); ok = false; }
  } finally {
    await browser.close();
    server.close();
  }
  if (ok) console.log("DOM Probe real-Chromium check: PASS");
  process.exit(ok ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(2); });
