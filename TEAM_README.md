# Project Guide for the Team — Read This First

**Project:** Identifying Prompt Injections in CLI Tools During Package
Installation using eBPF and ML
**Project ID:** PW26_PB04 | **Guide:** Prof. Priya Badrinath
**Team:** Aniruddha (CS076), Manikandan (CS277), Karthik (CS285), Komal (CS308)

---

# START HERE: What You Need To Do Right Now

**If you're Manikandan or Komal, read this section first. It tells you exactly
what to do, step by step, assuming you know nothing about the project.**

---

## What Is This Project? (30-Second Version)

When you type `npm install some-package`, that package can secretly run code
on your computer. Hackers use this to steal passwords, SSH keys, and secrets.

**Our solution:** We built a system that watches what packages do when they
install (using Linux kernel technology called eBPF) and uses machine learning
to decide if the package is safe or dangerous.

**The problem we're solving now:** Our ML model needs more training data.
We need to capture behavior from real packages (both safe and dangerous ones).

---

## Who Does What Right Now

**We're capturing packages in parallel to go 3× faster!**

| Person | Benign Packages | Malware Packages | Other Tasks |
|--------|-----------------|------------------|-------------|
| **Karthik** | 1-90 | 1-20 | Train ML model |
| **Komal** | 91-180 | 21-40 | GuardDog scan 1-100 |
| **Mani** | 181-270 | 41-60 | GuardDog scan 101-200 |

**Important:** Each person captures DIFFERENT packages. This way we get all ~270 benign packages AND ~60 malware packages captured in parallel.

---

# AWS VM SETUP INSTRUCTIONS (FOR EVERYONE)

**Read this section COMPLETELY before doing anything. Follow EXACTLY.**

These instructions work for Karthik, Komal, AND Mani. Each of you will create your own VM on your own AWS account.

---

## What is AWS? (If You Don't Know)

AWS (Amazon Web Services) is Amazon's cloud computing platform. We're using it to run a virtual Linux computer in the cloud. This VM (Virtual Machine) will run our eBPF monitor to capture what npm packages do when they install.

**Why a VM?** Because some packages we're testing might be malicious. We don't want to run them on our real computers. The VM is isolated - when we're done, we delete it and the malware is gone.

---

## PART A: Creating Your AWS Account (Skip if you already have one)

### Step A1: Go to AWS

1. Open your web browser (Chrome or Edge recommended - NOT Brave)
2. Go to: https://aws.amazon.com
3. Click "Create an AWS Account" (orange button, top right)

### Step A2: Fill in your details

1. Email: Use your personal email
2. AWS account name: Use something like "capstone-yourname"
3. Click "Verify email address"
4. Check your email for a verification code
5. Enter the code

### Step A3: Set a password

1. Create a strong password
2. Write it down somewhere safe

### Step A4: Contact information

1. Select "Personal" account type
2. Fill in your name, phone, address
3. Click "Continue"

### Step A5: Payment method

1. Enter a credit/debit card
2. **DON'T WORRY:** AWS Free Tier gives you 750 hours/month of t2.micro or t3.micro for FREE
3. We won't be charged if we follow these instructions

### Step A6: Identity verification

1. AWS will send a code to your phone
2. Enter the code

### Step A7: Select a support plan

1. Choose "Basic support - Free"
2. Click "Complete sign up"

**Wait 1-2 minutes for your account to be ready.**

---

## PART B: Creating Your VM Instance

### Step B1: Sign in to AWS Console

1. Go to: https://console.aws.amazon.com
2. Sign in with your email and password
3. You'll see the AWS Management Console

### Step B2: Go to EC2

1. In the search bar at the top, type: **EC2**
2. Click on "EC2" in the results (it says "Virtual Servers in the Cloud")

### Step B3: Pick your region

1. Look at the TOP RIGHT corner of the screen
2. You'll see a region name (like "N. Virginia" or "Ohio")
3. Click it and select: **EU (Stockholm)** or any region you prefer
4. **REMEMBER your region** - you'll need it later

### Step B4: Launch Instance

1. Click the orange "Launch instance" button
2. You'll see the instance creation page

### Step B5: Name your instance

1. In the "Name" field, type: **capstone-vm-capture**

### Step B6: Choose the operating system

1. Under "Application and OS Images (Amazon Machine Image)"
2. Make sure "Ubuntu" is selected (click on it if not)
3. In the dropdown below, select: **Ubuntu Server 24.04 LTS (HVM), SSD Volume Type**
   - **IMPORTANT:** Do NOT select "Ubuntu with SQL Server" or any other variant
   - It should say "Free tier eligible"

### Step B7: Choose instance type

1. Under "Instance type"
2. Select: **t3.micro** (it says "Free tier eligible")
   - If t3.micro isn't available, select **t2.micro**

### Step B8: Create a key pair (IMPORTANT!)

1. Under "Key pair (login)", click "Create new key pair"
2. Name: **capstone-key**
3. Key pair type: **RSA**
4. Private key file format: **PEM** (for Mac/Linux) or **PPK** (for Windows with PuTTY)
5. Click "Create key pair"
6. **A file will download - SAVE THIS FILE!** You need it to connect later
7. Put it somewhere safe like your Documents folder

### Step B9: Network settings (VERY IMPORTANT!)

1. Click "Edit" next to "Network settings"
2. Under "Firewall (security groups)", select "Create security group"
3. Security group name: **capstone-sg**
4. Description: **Security group for capstone VM**

5. You'll see a rule for SSH already there. Modify it:
   - Type: SSH
   - Port range: 22
   - Source type: Select **Custom**
   - Source: Enter **13.48.4.200/30**
   - Description: EC2 Instance Connect Stockholm

   **Why this specific IP?** This is AWS's own IP range for EC2 Instance Connect in Stockholm. It lets you connect through the browser.

6. Click "Add security group rule" to add HTTP:
   - Type: HTTP
   - Port range: 80
   - Source type: **Anywhere** (0.0.0.0/0)

7. Click "Add security group rule" to add HTTPS:
   - Type: HTTPS
   - Port range: 443
   - Source type: **Anywhere** (0.0.0.0/0)

### Step B10: Storage

1. Under "Configure storage"
2. Change "8" to **30** (GiB)
3. Keep "gp3" selected

### Step B11: Launch!

1. On the right side, click the orange "Launch instance" button
2. Wait for the green "Success" message
3. Click "View all instances"

### Step B12: Wait for your instance to start

1. You'll see your instance in the list
2. Wait until "Instance state" shows **Running** (green dot)
3. Wait until "Status check" shows **2/2 checks passed**
4. This takes 1-2 minutes

---

## PART C: Connecting to Your VM

### Step C1: Connect through the browser

1. In the EC2 instances list, click on your instance (the checkbox or the name)
2. Click the "Connect" button at the top
3. Select the "EC2 Instance Connect" tab
4. Leave username as **ubuntu**
5. Click the orange "Connect" button

**If you get an error "Failed to connect":**
- Go back to Step B9 and make sure your SSH security rule has source **13.48.4.200/30**
- If you're using a different region than Stockholm, you need a different IP range (ask Karthik)

### Step C2: You're in!

You should now see a black terminal with a prompt like:
```
ubuntu@ip-xxx-xxx-xxx-xxx:~$
```

**Congratulations! You're now inside your cloud VM.**

---

## PART D: Installing Everything We Need

**Copy and paste these commands ONE BY ONE.** After each command, wait for it to finish before running the next one.

### Step D1: Update the system

```bash
sudo apt-get update
```

Wait until you see the prompt again.

### Step D2: Install all required software

```bash
sudo apt-get install -y docker.io golang-go clang llvm libbpf-dev linux-headers-$(uname -r) make jq curl python3 iproute2 git build-essential
```

This takes 2-3 minutes. Wait for it to finish.

### Step D3: Enable Docker

```bash
sudo systemctl enable --now docker
```

### Step D4: Add yourself to the Docker group

```bash
sudo usermod -aG docker $USER
```

### Step D5: LOG OUT AND LOG BACK IN

**This is important!** The Docker group change only takes effect after you log out.

1. Type: `exit`
2. The browser window will say "Connection closed"
3. Go back to EC2 Console → Instances
4. Select your instance → Click "Connect" → Click "Connect" again

### Step D6: Verify Docker works

```bash
docker --version
```

You should see something like: `Docker version 24.x.x`

---

## PART E: Getting Our Code

### Step E1: Clone the repository

```bash
git clone https://github.com/JastiTheCoder/Machine_Learning_Hybrid_Model_for_EBPF.git
```

### Step E2: Go into the folder

```bash
cd Machine_Learning_Hybrid_Model_for_EBPF
```

### Step E3: Switch to the capture branch

```bash
git checkout feat/schema-unlock-and-capture-harness
```

---

## PART F: Building the Monitor

### Step F1: Build

```bash
make build
```

This takes 2-3 minutes. Wait for "Build complete" message.

### Step F2: Test that it works

```bash
sudo ./npm-ebpf-monitor -dry-run
```

You should see output about probes loading. If you see errors, STOP and ask Karthik.

---

## PART G: Safety Setup (CRITICAL!)

These commands block malware from stealing your cloud credentials.

### Step G1: Run the hardening script

```bash
sudo bash scripts/capture/harden-vm.sh
```

You might see a warning about iptables - that's OK, ignore it.

### Step G2: Open a SECOND terminal window

1. Go back to AWS Console in your browser
2. Keep your first terminal open
3. Select your instance → Click "Connect" → "EC2 Instance Connect" → "Connect"
4. You now have TWO terminal windows

### Step G3: Start the sinkhole (in the SECOND window)

```bash
cd Machine_Learning_Hybrid_Model_for_EBPF
sudo python3 scripts/capture/sinkhole.py --port 9999 --log /var/log/capture/sinkhole.jsonl
```

**Leave this running. Don't close this window.**

### Step G4: Go back to your FIRST terminal window

---

## PART H: Create Your Package List

**This is where each person does something DIFFERENT.**

### If you are KARTHIK:

```bash
head -n 90 scripts/capture/packages-benign.txt > ~/my-packages.txt
```

### If you are KOMAL:

```bash
sed -n '91,180p' scripts/capture/packages-benign.txt > ~/my-packages.txt
```

### If you are MANI:

```bash
tail -n 90 scripts/capture/packages-benign.txt > ~/my-packages.txt
```

### Verify your list:

```bash
wc -l ~/my-packages.txt
```

Should show approximately 90 packages.

```bash
head -5 ~/my-packages.txt
```

Shows first 5 packages (should be different for each person).

---

## PART I: Start Capturing!

### Step I1: Start the capture

```bash
sudo bash scripts/capture/capture.sh --list ~/my-packages.txt --label 0 --out /root/captures/benign
```

**What this does:**
- `--list ~/my-packages.txt` = use your personal package list
- `--label 0` = these are benign (safe) packages
- `--out /root/captures/benign` = save results here

**This takes 1-2 hours.** You can leave it running.

### Step I2: Check progress (optional)

Open a third terminal if you want to check progress:

```bash
ls /root/captures/benign/ | wc -l
```

This shows how many packages have been captured.

---

## PART I-2: Capture MALWARE Packages (After Benign is Done)

**⚠️ IMPORTANT: Only do this AFTER your benign capture completes!**

### Why We Need Malware Samples

Our ML model needs to learn what malicious packages look like. We're capturing known malicious packages so the model can learn the difference between safe and dangerous behavior.

### Safety Checklist (Before Capturing Malware)

- [ ] Hardening script was run (`sudo bash scripts/capture/harden-vm.sh`)
- [ ] Sinkhole is running in second terminal
- [ ] You've already captured your benign packages
- [ ] You understand: TERMINATE the VM after malware capture (don't reuse it)

### Step 1: Create Your Malware Package List

**If you are KARTHIK (malware packages 1-20):**
```bash
grep -v "^#" scripts/capture/packages-malware.txt | grep -v "^$" | head -n 20 > ~/my-malware.txt
```

**If you are KOMAL (malware packages 21-40):**
```bash
grep -v "^#" scripts/capture/packages-malware.txt | grep -v "^$" | sed -n '21,40p' > ~/my-malware.txt
```

**If you are MANI (malware packages 41-60):**
```bash
grep -v "^#" scripts/capture/packages-malware.txt | grep -v "^$" | tail -n 20 > ~/my-malware.txt
```

### Step 2: Verify Your List

```bash
wc -l ~/my-malware.txt
cat ~/my-malware.txt
```

Should show ~20 package names.

### Step 3: Capture Malware (Uses --label 1)

```bash
sudo bash scripts/capture/capture.sh --list ~/my-malware.txt --label 1 --out /root/captures/malware
```

**Note the differences from benign capture:**
- `--label 1` (not 0) — marks these as MALICIOUS
- `--out /root/captures/malware` (not benign)

### Step 4: Check Progress

```bash
ls /root/captures/malware/ | wc -l
```

### How Long Does Malware Capture Take?

**Much faster than benign!** Malware packages typically:
- Don't have many dependencies
- Do their malicious action quickly (steal and exit)
- Take 5-30 seconds each instead of 30-90 seconds

**Estimated time: 20 packages × 20 seconds = ~7-10 minutes**

### What If a Package Fails?

Some malicious packages may have been removed from npm. That's fine — the capture script will skip them and continue. You might get 15-18 successful captures out of 20, which is normal.

---

## PART J: When Capture Finishes

### Step J1: Check results

```bash
ls -la /root/captures/benign/
```

You should see many `.json` files.

### Step J2: Create a zip file

```bash
cd /root/captures
zip -r benign-YOURNAME.zip benign/
```

Replace YOURNAME with your actual name (e.g., benign-komal.zip).

### Step J3: Download the zip file

1. In your SSH terminal, run:
   ```bash
   ls -la /root/captures/benign-YOURNAME.zip
   ```
   Note the full path

2. In the EC2 Instance Connect window, click the gear icon (⚙️) in the top right
3. Click "Download file"
4. Enter the path: `/root/captures/benign-YOURNAME.zip`
5. Click "Download"

### Step J4: Send to Karthik

Send the zip file to Karthik via:
- Google Drive
- WhatsApp
- Email
- Whatever works

---

## PART K: STOP Your Instance (Important!)

**When you're done for the day or taking a break:**

1. Go to AWS Console → EC2 → Instances
2. Select your instance (checkbox)
3. Click "Instance state" dropdown
4. Click "Stop instance"
5. Confirm

**STOP vs TERMINATE:**
- **STOP** = Like putting your computer to sleep. You can start it again later. Your data is saved.
- **TERMINATE** = Like throwing your computer away. Everything is deleted forever.

**For now, use STOP. Only TERMINATE when you're 100% done with all captures.**

### To start it again later:

1. Go to AWS Console → EC2 → Instances
2. Select your instance
3. Click "Instance state" → "Start instance"
4. Wait for it to say "Running"
5. Connect again using EC2 Instance Connect

---

## KOMAL: Additional GuardDog Work

**After you finish your VM capture work, also do this on your laptop:**

### What is GuardDog?

GuardDog is a security tool that scans package SOURCE CODE for suspicious patterns. It doesn't run the code - it just reads it. This is called "static analysis."

Our project does "dynamic analysis" (watching what code DOES when it runs).

We're comparing both to show our method catches things GuardDog misses.

### Step 1: Install GuardDog on your laptop

Open PowerShell or Command Prompt:

```
pip install guarddog
```

### Step 2: Scan packages 1-100

For each package, run:

```
guarddog npm scan PACKAGE_NAME
```

The packages are listed in `scripts/capture/packages-benign.txt` (lines 1-100).

### Step 3: Record results in a spreadsheet

| Package Name | GuardDog Result | Findings |
|--------------|-----------------|----------|
| lodash | PASS | None |
| some-package | FAIL | obfuscation detected |

---

## MANI: Additional GuardDog Work

**After you finish your VM capture work, also do this on your laptop:**

Same as Komal, but scan packages 101-200 from the list.

---

## KARTHIK: Additional Tasks

After capturing your benign packages, you also need to:

1. **Capture malware samples** (only Karthik does this - requires special handling)
2. **Collect all JSON files from everyone**
3. **Train the ML model**
4. **Create comparison report**

---

## If Something Goes Wrong

| Problem | Solution |
|---------|----------|
| "Failed to connect" when clicking Connect | Check security group SSH rule is set to 13.48.4.200/30 |
| "Permission denied" errors | Make sure to use `sudo` before commands |
| `make build` fails | Run `sudo apt-get install -y build-essential` then try again |
| Docker commands fail | Did you log out and log back in after Step D5? |
| Instance won't start | Check your AWS Free Tier limits |
| Capture seems stuck | Check the sinkhole terminal - is it still running? |

---

## Quick Summary: What Each Person Does

### KARTHIK
1. ✅ VM already set up
2. ✅ Capture benign packages 1-90 (in progress)
3. Capture malware packages 1-20 (Part I-2)
4. Download your captures (Part J)
5. **TERMINATE** your VM after malware capture (Part K)
6. Collect files from Komal and Mani
7. Train ML model on combined dataset

### KOMAL
1. Create AWS VM (Part A-B)
2. Connect and set up (Part C-G)
3. Capture benign packages 91-180 (Part H-I)
4. Capture malware packages 21-40 (Part I-2)
5. Download and send to Karthik (Part J)
6. **TERMINATE** your VM after malware capture (Part K)
7. Scan packages 1-100 with GuardDog on laptop

### MANI
1. Create AWS VM (Part A-B)
2. Connect and set up (Part C-G)
3. Capture benign packages 181-270 (Part H-I)
4. Capture malware packages 41-60 (Part I-2)
5. Download and send to Karthik (Part J)
6. **TERMINATE** your VM after malware capture (Part K)
7. Scan packages 101-200 with GuardDog on laptop

### ⚠️ IMPORTANT: TERMINATE After Malware!

After capturing malware, **TERMINATE** (delete) your VM — don't just stop it:
1. AWS Console → EC2 → Instances
2. Select your instance
3. Instance state → **Terminate instance**
4. Confirm deletion

This destroys the VM completely. The malware touched the filesystem, so we don't want to reuse it.

---

## After Data Collection: What Happens Next

1. **Komal** sends her capture ZIP file + GuardDog spreadsheet (packages 1-100) to **Karthik**
2. **Mani** sends his capture ZIP file + GuardDog spreadsheet (packages 101-200) to **Karthik**
3. **Karthik** combines all capture files into one training dataset
4. **Karthik** trains the ML model on the combined data
5. **Karthik** merges both GuardDog spreadsheets and adds ML predictions
6. **Everyone** uses the comparison for the presentation

---

## If Something Goes Wrong

| Problem | Solution |
|---------|----------|
| "Failed to connect" in EC2 Instance Connect | Check security group SSH rule source is 13.48.4.200/30 (for Stockholm region) |
| VM won't create | Check Free Tier limits, try a different region, make sure you selected t3.micro or t2.micro |
| `make build` fails | Run `sudo apt-get install -y build-essential` first, then try again |
| Docker permission denied | Log out (`exit`) and log back in after adding yourself to docker group |
| `verify-harness.sh` fails | Screenshot the error and send to Karthik |
| Instance says "stopped" | Go to Instance state → Start instance, wait for "Running" |
| GuardDog won't install | Make sure Python is installed: `python --version` |
| GuardDog command not found | Try `python -m guarddog npm scan lodash` |
| "No space left on device" | You may have selected only 8GB storage - terminate and recreate with 30GB |

---

## Quick Reference: Commands to Copy-Paste

### For EVERYONE (on the VM) - Initial Setup:

```bash
# Install dependencies
sudo apt-get update && sudo apt-get install -y docker.io golang-go clang llvm libbpf-dev linux-headers-$(uname -r) make jq curl python3 iproute2 git build-essential

# Enable Docker
sudo systemctl enable --now docker
sudo usermod -aG docker $USER

# LOG OUT AND BACK IN, then:

# Get code
git clone https://github.com/JastiTheCoder/Machine_Learning_Hybrid_Model_for_EBPF.git
cd Machine_Learning_Hybrid_Model_for_EBPF
git checkout feat/schema-unlock-and-capture-harness

# Build
make build

# Test
sudo ./npm-ebpf-monitor -dry-run

# Safety setup
sudo bash scripts/capture/harden-vm.sh

# Start sinkhole (in SECOND terminal)
cd Machine_Learning_Hybrid_Model_for_EBPF
sudo python3 scripts/capture/sinkhole.py --port 9999 --log /var/log/capture/sinkhole.jsonl
```

### KARTHIK - Benign & Malware Capture:

```bash
# BENIGN: Create package list (packages 1-90)
grep -v "^#" scripts/capture/packages-benign.txt | grep -v "^$" | head -n 90 > ~/my-packages.txt

# BENIGN: Capture
sudo bash scripts/capture/capture.sh --list ~/my-packages.txt --label 0 --out /root/captures/benign

# MALWARE: Create package list (packages 1-20)
grep -v "^#" scripts/capture/packages-malware.txt | grep -v "^$" | head -n 20 > ~/my-malware.txt

# MALWARE: Capture (note: --label 1)
sudo bash scripts/capture/capture.sh --list ~/my-malware.txt --label 1 --out /root/captures/malware
```

### KOMAL - Benign & Malware Capture:

```bash
# BENIGN: Create package list (packages 91-180)
grep -v "^#" scripts/capture/packages-benign.txt | grep -v "^$" | sed -n '91,180p' > ~/my-packages.txt

# BENIGN: Capture
sudo bash scripts/capture/capture.sh --list ~/my-packages.txt --label 0 --out /root/captures/benign

# MALWARE: Create package list (packages 21-40)
grep -v "^#" scripts/capture/packages-malware.txt | grep -v "^$" | sed -n '21,40p' > ~/my-malware.txt

# MALWARE: Capture (note: --label 1)
sudo bash scripts/capture/capture.sh --list ~/my-malware.txt --label 1 --out /root/captures/malware
```

### MANI - Benign & Malware Capture:

```bash
# BENIGN: Create package list (packages 181-270)
grep -v "^#" scripts/capture/packages-benign.txt | grep -v "^$" | tail -n 90 > ~/my-packages.txt

# BENIGN: Capture
sudo bash scripts/capture/capture.sh --list ~/my-packages.txt --label 0 --out /root/captures/benign

# MALWARE: Create package list (packages 41-60)
grep -v "^#" scripts/capture/packages-malware.txt | grep -v "^$" | tail -n 20 > ~/my-malware.txt

# MALWARE: Capture (note: --label 1)
sudo bash scripts/capture/capture.sh --list ~/my-malware.txt --label 1 --out /root/captures/malware
```

### Download Results (everyone):

```bash
# Zip BOTH benign and malware results
cd /root/captures
zip -r all-captures-YOURNAME.zip benign/ malware/

# Then use the gear icon in EC2 Instance Connect to download
```

### GuardDog (Komal & Mani - on your laptop):

```bash
# Install
pip install guarddog

# Scan one package
guarddog npm scan lodash

# Scan multiple packages
guarddog npm scan lodash express axios chalk debug moment uuid dotenv
```

---

# The Rest of This Document

Everything below this line explains the project in depth — for understanding
the technical details and preparing for the presentation. Read it after you
finish your data collection tasks.

---

## 1. The problem in one paragraph

When a developer types `npm install some-package`, that command is allowed to
run arbitrary code on their laptop automatically, before the developer has
even looked at the package. This is a feature (packages need to set
themselves up) but attackers abuse it. Our specific angle: attackers are now
writing packages that, during install, go looking for the AI coding
assistants developers have on their machines (Claude, Copilot, Cursor) and
feed them malicious instructions — "prompt injection" — to make the trusted
AI tool do the dirty work: read SSH keys, read `.env` files, phone home.

Nobody catches this well today. Antivirus doesn't look at npm. Static code
scanners get defeated by obfuscation. Reputation systems can't help with a
brand-new package.

---

## 2. Our solution in one paragraph

We watch the installation from **inside the Linux kernel** using a technology
called **eBPF**, so the malicious code cannot hide from us or turn us off. We
record everything it does — every file opened, every network connection,
every system call — turn that recording into a row of numbers, and feed that
row to a **machine learning model** that decides "benign" or "malicious".

---

## 3. Vocabulary you must know (plain English)

| Term | What it actually means |
|---|---|
| **npm** | The app store for JavaScript code. `npm install x` downloads and sets up package x. |
| **PyPI / pip** | Same thing, but for Python. `pip install x`. |
| **Post-install script** | Code a package is allowed to run automatically right after download. This is the attack door. |
| **Syscall** | Any time a program wants to do something real (open a file, send data), it must ask the kernel. That request is a syscall. |
| **Kernel** | The core of the operating system. Every program must go through it. It sees everything. |
| **eBPF** | A safe way to run tiny observer programs *inside* the kernel. Near-zero slowdown, cannot be bypassed from userspace. This is our superpower. |
| **Probe** | One eBPF observer watching one specific thing (e.g. "tell me every file that gets opened"). |
| **Ring buffer** | A shared memory pipe that carries observations from kernel to our program without copying. Fast. |
| **Go daemon** | Our program that sits in userspace, drinks from the ring buffer, and tallies everything up. |
| **Session** | One complete `npm install` from start to finish. One session = one row of data. |
| **Feature** | One number describing the session. E.g. "how many times it touched /etc". |
| **Feature vector** | The full row of 36 numbers describing one session. |
| **QUT-DV25** | A public research dataset from Queensland University of Technology. 14,271 Python packages (about half malicious) that somebody else already recorded and labelled. We train our model on it because we don't have 14,000 samples of our own. |
| **Label** | The correct answer. 0 = benign, 1 = malicious. |
| **Recall** | Of all the genuinely malicious packages, what percentage did we catch? This is the number that matters most for security. |
| **In-distribution / Out-of-distribution (OOD)** | Does new data "look like" the data the model was trained on? If not, the model's predictions are meaningless. |
| **Domain shift** | When your test data systematically differs from your training data. Models break. |
| **n-gram** | A short sequence. A syscall 3-gram is three syscalls in a row, e.g. `read -> read -> close`. Repeating patterns are behavioural fingerprints. |

---

## 4. The pipeline, layer by layer

This is the part you will be asked to explain. There are six layers.

    LAYER 1  Kernel  — 4 eBPF probes watching the install
                |
    LAYER 2  Ring buffers — zero-copy pipe, kernel to userspace
                |
    LAYER 3  Go collectors — 5 goroutines reading the pipe
                |
    LAYER 4  Router + Session — sorts events into the right install session
                |
    LAYER 5  Aggregators — turn raw events into 36 numbers
                |
    LAYER 6  Output — JSON file + CSV row -> ML model -> verdict

### Layer 1 — The four eBPF probes

| Probe | Watches | Why we need it |
|---|---|---|
| **Process Tracer** | Programs starting and stopping | npm spawns dozens of child processes. We must follow all of them, including any AI CLI tool it launches. |
| **Syscall Tracer** | Every system call | Gives us the behavioural fingerprint (the n-grams). |
| **File Monitor** | Every file open | Catches access to `~/.ssh/id_rsa`, `.env`, `/etc/shadow`. |
| **TCP Monitor** | Network connections | Catches data being sent out (exfiltration). |

All four share one lookup table called `tracked_pids`. The Process Tracer
puts the npm process in it, and every child gets added automatically. The
other three probes check this table before recording anything — that's how we
only record *our* install and not the rest of your computer.

### Layer 5 — The 36 features (grouped)

| Group | Count | Examples |
|---|---|---|
| Filetop | 5 | how many processes read/wrote, how many KB |
| Install | 3 | number of dependencies |
| Directory access | 7 | accesses to /root, /tmp, /home, /etc, ... |
| Network (TCP) | 5 | connection state changes, unique remote IPs/ports |
| Syscall categories | 6 | file ops, network ops, IO ops, security ops, ... |
| N-gram patterns | 10 | the 10 most frequent syscall 3-grams |

36 features + `package_name` + `label` + `severity_score` = **39 columns**
in our exported CSV.

### Layer 6 — Two things decide "malicious"

1. **Verdict engine** (rule-based, added this phase). 12 handwritten rules,
   each tagged with a MITRE ATT&CK technique. Two are *decisive* — if they
   fire, the session is malicious no matter what the score is:
   - `PERSIST-001` — wrote into a startup/cron location (it wants to survive reboot)
   - `EXFIL-001` — read something sensitive, *then* opened a network connection

   This is fast, explainable, and needs no ML.
2. **ML model** (Random Forest / XGBoost). Trained on QUT-DV25, gives a
   probability. This is the part with the open problem — see section 6.

---

## 5. What we built in Phase 2 (already submitted)

- All four eBPF probes working, CO-RE portable across kernel versions
- Go daemon with the full session pipeline
- 36-feature JSON + CSV export matching QUT-DV25's schema
- Hybrid XGBoost + LSTM model
- Measured performance: **under 4% CPU overhead, zero dropped events**
- **Reported result: 96.67% accuracy on the QUT test set, and we claimed
  "perfect recall" on our own eBPF sessions.**

That last claim turned out to be wrong. Finding that out is most of Phase 3.

---

## 6. What happened in Phase 3 (the investigation)

This is the interesting part and the strongest thing we have to present.
It reads like a detective story, so learn it as one.

**Step 1 — The alarm.** We re-ran the model properly on 24 real npm captures.
Result: it classified every single benign package correctly, and **caught 0
out of 6 malicious packages. 0% recall.** The Phase 2 "perfect recall" claim
came from a tiny 10-session balanced pool and did not survive a bigger test.

**Step 2 — First theory: wrong ecosystem.** QUT-DV25 is Python/PyPI data. We
were testing on JavaScript/npm. Maybe the model simply can't read npm.
Aniruddha rewrote the monitor to also support `pip install` and captured 3
PyPI packages, so we could test the theory.

**Step 3 — The distance test.** Rather than measure accuracy on 3 samples
(meaningless), we asked a better question: *do these rows even look like
QUT-DV25's data?* We measured how far each of our rows sat from its nearest
QUT-DV25 neighbour, and compared that to how far QUT-DV25's own rows sit from
each other. Result: our PyPI rows were **505 standard deviations** away.
Absurd. That's not domain shift, that's a bug.

**Step 4 — The bug.** Two of them, actually.

- The handoff document had an **off-by-one column mapping error** — it listed
  a column (`unknown_ops`) that the exporter never actually writes, so
  columns 29–39 were all shifted by one. Anyone building a feature map from
  that table was silently mapping the wrong data.
- Worse: QUT-DV25's `Pattern_1..10` columns are **not counts**. They are the
  *identity* of the most frequent 3-gram — a text string like
  `newfstatat -> newfstatat -> newfstatat`. Our code was counting keyword
  occurrences and getting ~2,560, then comparing that against QUT's strings
  converted to category codes 0–5. **We were comparing a count to a category
  label.** The 505σ was real arithmetic on meaningless inputs.

**Step 5 — Sanity check the pipeline.** Before trusting anything, we checked
whether our own ML code could reproduce the QUT-DV25 paper's published
result. Paper says 95.99% accuracy / 96.02% F1. **We got 97.30% / 97.27%.**
Our pipeline is sound. Good — the bug is in the data mapping, not the model.

**Step 6 — The fix.** QUT publishes raw trace files for 200 of its packages.
Aniruddha recomputed the real 3-gram *counts* from those raw files using the
exact same algorithm our monitor uses, producing a 196-package reference set.
Now we could compare count against count — apples to apples.

**Step 7 — The clean answer.** With the correct comparison:

- PyPI rows sit at the **73.5th percentile** of QUT-DV25's own spread
- npm rows sit at the **78.3rd percentile**
- Anything under the 95th percentile counts as in-distribution

**Both ecosystems are IN-DISTRIBUTION.** The data was never alien. The 0%
recall was never a domain-shift problem. It was an encoding bug.

**Step 8 — But recall is still 0%.** We retrained on the corrected reference
set (93.4% cross-validation accuracy) and tested on our captures. Still 0
out of 7 malicious caught. So we looked at *why*:

| | Benign `p1_count` | Malicious `p1_count` |
|---|---|---|
| **QUT-DV25** | median 3,235 | median **1,678** |
| **Our captures** | median 2,824 | median **2,812** |

In QUT-DV25, real malware does *less* work than benign packages — it skips
the real installation and just steals and exits. The model correctly learned
"low activity = malicious."

Our malicious test packages are **hand-written fixtures that do a full,
normal installation and then also do something bad**. So their activity level
is identical to benign. The model isn't broken — it's answering a question
about a different kind of malware than the kind we built.

**This is called the provenance gap:** QUT has 7,127 *real* malicious
packages collected from the wild; we have 7 *synthetic* ones we wrote
ourselves, because you cannot safely install real malware on a capture
machine.

---

## 7. What Phase 3 actually delivers

1. A working **PyPI/pip capture path** alongside npm (the monitor is no
   longer npm-only)
2. **Schema 2.0.0** — 44 columns, now exporting both the winning n-gram
   *and* its count, so no future consumer has to guess
3. A **corrected feature contract** — the off-by-one column bug is fixed and
   the table is now generated from the exporter's real header
4. A **rebuilt QUT reference set** (196 packages with true frequency counts,
   reconstructed from raw traces)
5. **Reproduction of the published benchmark** at 97.30% — proof our pipeline
   is correct
6. A rigorous **out-of-distribution study** proving both ecosystems are
   in-distribution, and an honest correction of Phase 2's recall claim
7. The **verdict engine** — 12 explainable MITRE-tagged rules that catch our
   malicious fixtures *today*, without any ML

Point 7 matters: **the rule engine works even though the ML doesn't yet.**
Our malicious fixtures do get flagged, by the rules.

---

## 8. What is still open (say this honestly if asked)

- **ML recall on our fixtures is 0%**, and we know exactly why (provenance
  gap, section 6 step 8). Not a mystery, a documented limitation.
- ~17 of the 36 features are measured differently by QUT (system-wide) than
  by us (process-scoped). Deliberate — matching them would mean polluting our
  captures with unrelated desktop noise.
- Our benign PyPI arm is one synthetic fixture; the npm side has 8 real
  registry packages.
- Next real step: either collect a much larger corpus of our own, or source
  real malicious samples so the training data matches our threat model.

---

## 9. The 60-second version (memorise this)

> Package managers run code automatically at install time, and attackers use
> that to hijack the AI coding tools developers have installed. We watch the
> install from inside the Linux kernel with eBPF, which malware can't evade,
> and turn each install into 36 behavioural numbers. Those go to a rule engine
> and an ML classifier.
>
> In Phase 3 we added PyPI support, and we investigated why our model scored
> 0% recall. We found it was a feature-encoding bug, not a domain-shift
> problem — we proved that by reproducing the source paper's benchmark at
> 97.3% and by showing both ecosystems are statistically in-distribution once
> the encoding is fixed. The remaining recall gap is a provenance gap: the
> public dataset's malware is real and does minimal work, ours is synthetic
> and does a full install. Our rule engine catches them regardless.

---

## 10. Phase 2 → Phase 3 change table

This is what the panel will actually grade.

| Area | Phase 2 (submitted) | Phase 3 (now) |
|---|---|---|
| Ecosystems | npm only | npm **and** PyPI/pip |
| Schema | 39 columns, v1.0.0 | **44 columns, v2.0.0** — exports `pN_ngram` *and* `pN_count` |
| Feature contract | Off-by-one error; listed `unknown_ops` as col 29, shifting cols 29–39 | **Fixed**, table generated from the exporter's real header |
| Decision layer | ML only | ML **+ 12-rule verdict engine** with MITRE tags, 2 decisive rules |
| Evidence | Directory *counts* only | **Path classification** (13 classes) + argv classification (5 classes) + first-seen timestamps, enabling ordering rules |
| Claimed recall | "Perfect recall for the malicious class" | **Corrected to 0%** on a larger 24-sample test — with root cause identified |
| Benchmark validation | Not done independently | **Reproduced the QUT paper at 97.30% vs their 95.99%** |
| OOD analysis | None | Full nearest-neighbour + percentile study; both ecosystems in-distribution |
| Ground truth | 6 synthetic fixtures | + 8 real npm registry packages (lodash, express, chalk, debug, axios, moment, uuid, dotenv) |
| Known bugs closed | C1–C4, H1–H3, H5 | + `FileEvent` struct padding bug (corrupted every timestamp), session double-completion race, silent event drops now counted |

**Important framing:** Phase 2's abstract claims "perfect recall for the
malicious class." Phase 3 contradicts that. Do **not** hide it — lead with it.
"We stress-tested our own Phase 2 result, found it didn't hold at larger
sample size, and spent Phase 3 finding out exactly why" is a much stronger
story than a number nobody checked.

---

## 11. Where the evidence lives

| What | Path |
|---|---|
| Benchmark reproduction result | `ml_analysis/outputs/qut_benchmark_results.csv` |
| OOD comparison (schema 2.0.0) | `ml_analysis/outputs/ood_comparison_schema2.csv` |
| Count-vs-count NN distances | `ml_analysis/outputs/pypi_nn_count_vs_count.csv`, `npm_nn_count_vs_count.csv` |
| Predictions after corrected alignment | `ml_analysis/outputs/corrected_alignment_predictions.csv` |
| Full OOD write-up | `ml_analysis/OOD_ANALYSIS_REPORT.md` |
| Architecture changes this phase | `docs/ARCHITECTURE_CHANGES.md` |
| Open findings / audit | `docs/NEW_AUDIT.md` |
| PyPI rewrite step-by-step | `docs/pypi-rewrite/` (on branch `feat/pypi-rewrite`) |
| Feature column contract | `docs/ml_handoff.md` |

---

## 12. Who does what for the Phase 3 deck

> **Assumption:** this maps to the standard PES ESA slide structure. If the
> Phase 3 template mandates a different slide list, keep the *ownership split*
> below and just remap the slide numbers.

### Reading guide — do this before you start

| Person | Must read in depth | Can skim |
|---|---|---|
| **Mani** | Sections 1, 2, 3, 4, 5 | 6, 7, 8 |
| **Komal** | Sections 6, 7, 8, 10, 11 | 1, 2, 3 |

Both of you must read **section 6**. It is the longest section and the most
tempting to skip. If you skip it you will present a contradiction to the
panel without realising it, because section 5 ends on a claim that section 6
overturns.

---

### Mani — Narrative & context (slides 1–10)

You own everything up to the architecture. You do **not** need to understand
the ML investigation to do your part.

| # | Deliverable | Where the material is |
|---|---|---|
| 1 | Title / team / guide slide | Phase 2 dissertation p.1 — copy it, update "Phase 2" to "Phase 3" |
| 2 | Problem Statement (2 slides) | Section 1 of this doc. Phase 2's framing was good — reuse it |
| 3 | Motivation — real incidents | Phase 2 §2.3: event-stream (2018), ua-parser-js (2021), nx compromise. Add one 2026 incident if you can find a credible source |
| 4 | Literature Survey refresh | Phase 2 Ch.2 already has 8 papers. **Your one new contribution:** add a critique slide on QUT-DV25's methodology — that their `Pattern_N` columns are frequency *ranks* (which 3-gram won), not semantic categories as the appendix table implies, and that their published CSV omits the counts their paper says they trained on. We found this ourselves. It is a genuine, citable finding |
| 5 | Objectives — Phase 3 specific | Derive from section 7 of this doc |
| 6 | Phase 2 recap (1 slide, move fast) | Section 5 of this doc |
| 7 | Architecture recap | Reuse Phase 2 Figures 1–4 unchanged |

**Estimated effort: ~6 hours.**

**Watch out for:** on slide 6, state the Phase 2 recall claim as *"what we
reported in Phase 2"* — not as a current fact. Komal's slides immediately
after yours will correct it. If you assert it as still true, the deck
contradicts itself.

---

### Komal — Results, figures & formatting (slides 11–22)

You own the results half and the overall look of the deck. Your slides carry
the Phase 3 story, so section 6 of this doc is your script.

| # | Deliverable | Where the material is |
|---|---|---|
| 1 | Updated architecture diagram | Phase 2 Fig 1, plus one new box for the verdict engine after the aggregation layer. Exact flow is in `docs/ARCHITECTURE_CHANGES.md` §5 |
| 2 | **Phase 2 → Phase 3 comparison table** | Section 10 of this doc. This is the single most important slide in the deck — the panel is grading delta |
| 3 | Benchmark reproduction | `ml_analysis/outputs/qut_benchmark_results.csv`. Two-row table: Paper 95.99% / 96.02% vs Ours 97.30% / 97.27% |
| 4 | The investigation (3 slides) | Section 6, steps 1→8. One slide per act: **the alarm** (steps 1–2), **the bug** (steps 3–4), **the clean answer** (steps 5–7) |
| 5 | OOD result | `ml_analysis/outputs/ood_comparison_schema2.csv` plus the count-vs-count figures: PyPI 73.5th percentile, npm 78.3rd, threshold 95th |
| 6 | The provenance gap | Section 6 step 8 — reproduce that four-cell median table as-is. It explains the 0% recall in one visual, better than any paragraph |
| 7 | Verdict engine | 12 rules, 2 decisive, MITRE-tagged. `docs/ARCHITECTURE_CHANGES.md` §5 |
| 8 | Performance | Reuse Phase 2 §6.2 unchanged — under 4% CPU, zero dropped events |
| 9 | Limitations & Future Work | Section 8 of this doc |
| 10 | References | Phase 2 Ch.8 as-is. Add entries only if Manikandan sources a new paper |
| 11 | Whole-deck formatting pass | Fonts, figure captions, slide numbers, consistent table styling |

**Estimated effort: ~10 hours.**

**Watch out for:** slide 4 is a story, not a data dump. Deliver it in that
order — *we found a problem, we found the cause, we proved the cause*. If you
lead with the 505σ number without the setup, it reads as a failure rather
than as the diagnostic win it actually was.

---

### Karthik — retained (not delegated)

- ML methodology — expect the hard questions here
- Live demo, if there is a slot
- Q&A defence on why 0% recall is a *finding* and not a failure

### Aniruddha — already covered

The `docs/pypi-rewrite/` step documents are the implementation evidence for
the PyPI work. No additional slide-writing needed from him.

---

### Suggested two-day schedule

| When | Mani | Komal |
|---|---|---|
| **Day 1 morning** | Read sections 1–6 | Read sections 6–11 |
| **Day 1 afternoon** | Slides 1–5 drafted | Slides 1–4 drafted (arch diagram + comparison table first) |
| **Day 1 evening** | Send drafts to Karthik for a factual check | Same |
| **Day 2 morning** | Slides 6–7, incorporate feedback | Slides 5–9, incorporate feedback |
| **Day 2 afternoon** | Hand deck to Komal | Merge both halves, formatting pass |
| **Day 2 evening** | Full team dry run, both must be able to deliver section 9 from memory | Same |

**Hard rule for the dry run:** each person must be able to explain their own
slides *without* reading them, and must be able to answer "what changed since
Phase 2" using section 10. If either of you can't do that, the split has
failed and we redistribute.
