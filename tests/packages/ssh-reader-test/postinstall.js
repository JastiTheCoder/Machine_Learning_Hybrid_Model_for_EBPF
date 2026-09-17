/**
 * TEST PACKAGE - Simulates SSH key reading attack
 * 
 * This is a SAFE test package for ML training. It:
 * 1. Attempts to list and read files in ~/.ssh
 * 2. Attempts to read ~/.aws/credentials
 * 
 * The eBPF monitor will capture these file access patterns for training.
 * Note: This doesn't actually exfiltrate data - just reads files.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

console.log('[ssh-reader-test] Postinstall script running...');

const homeDir = os.homedir();

// Sensitive directories that attackers target
const sensitiveLocations = [
  path.join(homeDir, '.ssh'),
  path.join(homeDir, '.aws'),
  path.join(homeDir, '.gnupg'),
  path.join(homeDir, '.config', 'gcloud')
];

let filesAccessed = 0;

sensitiveLocations.forEach(dir => {
  console.log(`[ssh-reader-test] Checking: ${dir}`);
  
  try {
    if (fs.existsSync(dir)) {
      const files = fs.readdirSync(dir);
      console.log(`[ssh-reader-test] Found ${files.length} files in ${dir}`);
      
      files.forEach(file => {
        const filePath = path.join(dir, file);
        try {
          // Attempt to read the file (generates file_ops syscalls)
          const stats = fs.statSync(filePath);
          if (stats.isFile() && stats.size < 10000) {
            fs.readFileSync(filePath);
            filesAccessed++;
            console.log(`[ssh-reader-test] Read: ${file}`);
          }
        } catch (e) {
          // Permission denied is expected
          console.log(`[ssh-reader-test] Cannot read: ${file}`);
        }
      });
    }
  } catch (e) {
    console.log(`[ssh-reader-test] Cannot access: ${dir}`);
  }
});

console.log(`[ssh-reader-test] Total files accessed: ${filesAccessed}`);
console.log('[ssh-reader-test] Postinstall complete');
