# Training Data Expansion Plan

**Goal:** Expand from 307 samples to ~1500+ samples to match Aniruddha's 4500  
**Source:** Datadog Malicious Software Packages Dataset  
**Timeline:** ~4 hours per person  

---

## Datadog Dataset Overview

**Repository:** https://github.com/DataDog/malicious-software-packages-dataset

| Info | Value |
|------|-------|
| Total Malicious Packages | 29,847 |
| Ecosystems | npm, PyPI, IDE extensions, AI Skills |
| Format | Encrypted ZIP (password: `infected`) |
| Location | `samples/npm/`, `samples/pypi/` |

---

## Task Distribution

### Summary

| Person | Benign Packages | Malware Packages | Total | Time |
|--------|----------------|------------------|-------|------|
| **Karthik** | 300 | 200 | 500 | ~4 hours |
| **Mani** | 300 | 200 | 500 | ~4 hours |
| **Komal** | 300 | 200 | 500 | ~4 hours |
| **TOTAL** | 900 | 600 | 1500 | - |

Combined with existing 307 samples = **~1800 samples**

---

## Phase 1: Setup (All Team Members)

### Step 1.1: Clone the Datadog Dataset

```bash
# On your local machine (NOT the VM yet)
git clone https://github.com/DataDog/malicious-software-packages-dataset.git
cd malicious-software-packages-dataset
```

### Step 1.2: Extract npm Malware Package Names

```bash
# List all npm malware packages
ls samples/npm/ | head -50

# Or use the manifest file
cat samples/npm/manifest.json | python3 -c "import sys,json; d=json.load(sys.stdin); print('\n'.join(d.keys()))" | head -100
```

### Step 1.3: Create Your Package Lists

**Save the package names to text files:**

```bash
# Get all npm malware package names
cat samples/npm/manifest.json | python3 -c "
import sys, json
d = json.load(sys.stdin)
for pkg in d.keys():
    print(pkg)
" > all-npm-malware.txt

# Count total
wc -l all-npm-malware.txt
```

---

## Phase 2: Split the Work

### Creating Individual Package Lists

**Karthik's malware list (packages 1-200):**
```bash
head -n 200 all-npm-malware.txt > karthik-malware.txt
```

**Mani's malware list (packages 201-400):**
```bash
sed -n '201,400p' all-npm-malware.txt > mani-malware.txt
```

**Komal's malware list (packages 401-600):**
```bash
sed -n '401,600p' all-npm-malware.txt > komal-malware.txt
```

### Benign Package Lists

Use npm's top packages (different from what we already captured):

**Top npm packages source:**
- https://www.npmjs.com/browse/depended
- https://github.com/nice-registry/all-the-package-names

**Karthik's benign list (packages 271-570):**
```bash
# Skip first 270 (already captured), take next 300
sed -n '271,570p' scripts/capture/packages-benign.txt > karthik-benign.txt
```

**Mani's benign list (packages 571-870):**
```bash
# Add more packages to packages-benign.txt first, then:
sed -n '571,870p' scripts/capture/packages-benign-extended.txt > mani-benign.txt
```

**Komal's benign list (packages 871-1170):**
```bash
sed -n '871,1170p' scripts/capture/packages-benign-extended.txt > komal-benign.txt
```

---

## Phase 3: VM Setup (Each Person)

### Step 3.1: Create Google Cloud VM

Follow the existing instructions in `TEAM_README.md` Part A-B, but use:
- **Machine type:** e2-medium (2 vCPU, 4GB RAM) - faster captures
- **Disk:** 50GB (more space for malware)
- **Region:** Same as before

### Step 3.2: Install Dependencies

```bash
# Update system
sudo apt-get update

# Install dependencies
sudo apt-get install -y docker.io golang-go clang llvm libbpf-dev \
    linux-headers-$(uname -r) make jq curl python3 iproute2 git build-essential unzip

# Enable Docker
sudo systemctl enable --now docker
sudo usermod -aG docker $USER

# LOG OUT AND LOG BACK IN
exit
```

### Step 3.3: Clone and Build

```bash
git clone https://github.com/JastiTheCoder/Machine_Learning_Hybrid_Model_for_EBPF.git
cd Machine_Learning_Hybrid_Model_for_EBPF
git checkout feat/schema-unlock-and-capture-harness
make build
```

### Step 3.4: Run Safety Hardening

```bash
sudo bash scripts/capture/harden-vm.sh
```

### Step 3.5: Start Sinkhole (Second Terminal)

```bash
cd Machine_Learning_Hybrid_Model_for_EBPF
sudo python3 scripts/capture/sinkhole.py --port 9999 --log /var/log/capture/sinkhole.jsonl
```

---

## Phase 4: Capture Process

### Step 4.1: Upload Your Package Lists to VM

```bash
# From your local machine, use SCP or paste into a file
scp karthik-malware.txt karthik-benign.txt user@vm-ip:~/
```

### Step 4.2: Capture Benign Packages First

```bash
# Create output directory
sudo mkdir -p /root/captures/benign-new

# Start capture (in first terminal)
sudo bash scripts/capture/capture.sh \
    --list ~/karthik-benign.txt \
    --label 0 \
    --out /root/captures/benign-new
```

**Estimated time:** 300 packages × 30 sec = ~2.5 hours

### Step 4.3: Capture Malware Packages

```bash
# Create output directory
sudo mkdir -p /root/captures/malware-new

# Start capture (note: --label 1 for malware)
sudo bash scripts/capture/capture.sh \
    --list ~/karthik-malware.txt \
    --label 1 \
    --out /root/captures/malware-new
```

**Estimated time:** 200 packages × 20 sec = ~1.5 hours

### Step 4.4: Check Progress

```bash
# In another terminal
ls /root/captures/benign-new/ | wc -l
ls /root/captures/malware-new/ | wc -l
```

---

## Phase 5: Download Results

### Step 5.1: Create ZIP Files

```bash
cd /root/captures

# Zip benign captures
sudo tar -czvf benign-YOURNAME.tar.gz benign-new/

# Zip malware captures  
sudo tar -czvf malware-YOURNAME.tar.gz malware-new/
```

### Step 5.2: Download via EC2 Instance Connect

1. Click gear icon (⚙️) in terminal
2. Select "Download file"
3. Enter path: `/root/captures/benign-YOURNAME.tar.gz`
4. Repeat for malware file

### Step 5.3: Send to Karthik

Send both files via:
- Google Drive
- WhatsApp
- Email

---

## Phase 6: TERMINATE VM (Critical!)

**After downloading your captures:**

```bash
# IMPORTANT: Destroy the VM completely
# Do NOT just stop it - malware touched the filesystem
```

1. Go to Google Cloud Console
2. Select your VM instance
3. Click **DELETE** (not Stop)
4. Confirm deletion

---

## Timeline Summary

| Phase | Task | Time |
|-------|------|------|
| 1 | Clone Datadog dataset, extract package names | 30 min |
| 2 | Create individual package lists | 15 min |
| 3 | Set up VM | 30 min |
| 4 | Capture benign packages | ~2.5 hours |
| 4 | Capture malware packages | ~1.5 hours |
| 5 | Download results | 15 min |
| 6 | Terminate VM | 5 min |
| **TOTAL** | | **~5 hours** |

---

## After All Captures Are Done

### Karthik's Tasks:

1. **Collect all captures from team:**
   - benign-karthik.tar.gz, malware-karthik.tar.gz
   - benign-mani.tar.gz, malware-mani.tar.gz
   - benign-komal.tar.gz, malware-komal.tar.gz

2. **Extract and organize:**
   ```bash
   cd capstone/captures
   
   # Extract benign
   tar -xzvf benign-karthik.tar.gz -C benign/
   tar -xzvf benign-mani.tar.gz -C benign/
   tar -xzvf benign-komal.tar.gz -C benign/
   
   # Extract malware
   tar -xzvf malware-karthik.tar.gz -C malware/
   tar -xzvf malware-mani.tar.gz -C malware/
   tar -xzvf malware-komal.tar.gz -C malware/
   ```

3. **Retrain model:**
   ```bash
   python ml_analysis/cross_validation_proper.py \
       --benign captures/benign \
       --malware captures/malware
   ```

4. **Update API with new model:**
   ```bash
   # Delete old model files to force retraining
   rm ml_analysis/model.pkl ml_analysis/scaler.pkl
   
   # Start API (will auto-train on new data)
   python -m uvicorn ml_analysis.api:app --host 0.0.0.0 --port 8000
   ```

---

## Expected Results After Expansion

| Metric | Current (307 samples) | Expected (~1800 samples) |
|--------|----------------------|--------------------------|
| Recall | 76.8% | 85-90% |
| Precision | 95.6% | 90-95% |
| Accuracy | 95.1% | 92-95% |

More training data = better generalization = higher recall on real malware.

---

## Safety Reminders

⚠️ **NEVER run malware on your personal computer**  
⚠️ **ALWAYS use isolated VMs**  
⚠️ **ALWAYS run hardening script before capturing malware**  
⚠️ **ALWAYS terminate (delete) VMs after malware capture**  
⚠️ **NEVER reuse a VM that touched malware**  

---

## Questions?

Contact Karthik for coordination.
