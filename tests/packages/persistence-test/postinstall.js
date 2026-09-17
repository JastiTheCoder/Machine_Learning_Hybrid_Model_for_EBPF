/**
 * TEST PACKAGE - Simulates persistence/backdoor installation
 * 
 * This is a SAFE test package for ML training. It:
 * 1. Attempts to write to startup/cron locations (will mostly fail)
 * 2. Attempts to modify shell config files
 * 
 * The eBPF monitor will capture these write attempts for training.
 * Note: Most writes will fail due to permissions - but syscalls are logged.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

console.log('[persistence-test] Postinstall script running...');

const homeDir = os.homedir();
const isLinux = os.platform() === 'linux';

// Persistence locations that attackers typically target
const persistenceTargets = [
  // Shell config files
  { path: path.join(homeDir, '.bashrc'), action: 'append', content: '# test-entry' },
  { path: path.join(homeDir, '.zshrc'), action: 'append', content: '# test-entry' },
  { path: path.join(homeDir, '.profile'), action: 'append', content: '# test-entry' },
  
  // Cron directories (will fail without root)
  { path: '/etc/cron.d/testjob', action: 'write', content: '# test cron' },
  { path: '/var/spool/cron/crontabs/root', action: 'write', content: '# test' },
  
  // Systemd user services
  { path: path.join(homeDir, '.config/systemd/user/test.service'), action: 'write', content: '[Service]' },
  
  // Autostart
  { path: path.join(homeDir, '.config/autostart/test.desktop'), action: 'write', content: '[Desktop Entry]' }
];

let attempts = 0;
let successes = 0;

persistenceTargets.forEach(target => {
  attempts++;
  console.log(`[persistence-test] Attempting: ${target.path}`);
  
  try {
    // Ensure parent directory exists
    const dir = path.dirname(target.path);
    if (!fs.existsSync(dir)) {
      try {
        fs.mkdirSync(dir, { recursive: true });
      } catch (e) {
        // Expected to fail for system directories
      }
    }
    
    if (target.action === 'append') {
      fs.appendFileSync(target.path, `\n${target.content}\n`);
      successes++;
      console.log(`[persistence-test] SUCCESS: Appended to ${target.path}`);
    } else {
      fs.writeFileSync(target.path, target.content);
      successes++;
      console.log(`[persistence-test] SUCCESS: Wrote to ${target.path}`);
    }
  } catch (e) {
    // Expected to fail for most system locations
    console.log(`[persistence-test] FAILED: ${e.code || e.message}`);
  }
});

console.log(`[persistence-test] Results: ${successes}/${attempts} successful`);
console.log('[persistence-test] Postinstall complete');
