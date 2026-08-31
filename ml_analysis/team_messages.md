# Team Coordination Messages

Use these messages to assign tasks to your teammates.

---

## Message for Aniruddha (Fresh Data Capture)

**Subject: Need fresh session captures with bug fixes**

```
Hey Aniruddha,

I ran the ML analysis on our current session data and found some important issues:

1. **C1 Bug Confirmed**: All sessions have write_processes = 0. The analysis shows this is affecting our data quality.

2. **TCP Features are Key**: The malicious package shows 4x higher TCP activity - this is our best discriminator!

I need you to:
1. Merge your `fix/audit-critical-findings` branch into main
2. Re-capture sessions for these packages with the fixed monitor:
   - lodash (benign baseline)
   - benign-test (our test benign package)
   - suspicious-test (our test malicious package)
   - env-stealer-test (if available)
   
3. Send me the new JSON files from the sessions/ folder

The report is due in 2 days, so if you can get me the files by tomorrow morning, I can re-run the analysis with clean data.

Thanks!
Karthik
```

---



## Message for Manikandan (Problem Statement Section)

**Subject: Report section assignment - Problem Statement**

```
Hey Manikandan,

I need you to write the Problem Statement and Background section for our Phase 3 report. Here are the bullet points to expand into paragraphs:

### Problem Statement (expand each into 1-2 paragraphs)

1. **The Growing Threat**
   - npm (Node Package Manager) hosts millions of packages used by developers worldwide
   - Developers run "npm install" without thinking - it automatically executes code
   - Attackers have discovered they can hide malicious code in packages
   - Real examples: event-stream attack (2018) stole Bitcoin, ua-parser-js (2021) installed crypto miners

2. **The AI CLI Attack Vector** (Our specific focus)
   - AI coding assistants (GitHub Copilot, Claude, Cursor) can be tricked
   - "Prompt injection" attacks make the AI run dangerous commands
   - Example: A malicious README could tell the AI to install a bad package
   - This is new and most security tools don't catch it

3. **Why Existing Defenses Fail**
   - Static analysis: Can't catch obfuscated (hidden) malicious code
   - Reputation systems: New packages have no history to check
   - Sandboxing: Too slow for real development workflows
   - Package signing: Doesn't verify what the code actually DOES

### Why Kernel-Level Monitoring (1 page)

1. **What is kernel-level monitoring?**
   - The kernel is the core of the operating system
   - Every program must ask the kernel for permission to do things
   - We watch EVERY file access, network connection, and process creation

2. **Why eBPF specifically?**
   - eBPF lets us run tiny programs inside the Linux kernel
   - Near-zero performance impact (unlike traditional debugging)
   - Cannot be evaded by malicious code (kernel sees everything)
   - Real-time detection during package installation

3. **Our Approach**
   - Wrap "npm install" with our eBPF monitor
   - Collect behavioral data (syscalls, file access, network activity)
   - Feed to ML model for classification
   - Alert user before damage is done

Let me know if you need clarification on any points!

Karthik
```

---



## Message for Komal (Report Formatting and Figures)

**Subject: Report formatting and figure captions needed**

```
Hey Komal,

I've generated all the ML analysis figures. I need your help formatting them for the report.

### Figures Location
All figures are in: capstone/ml_analysis/figures/

### Figures to Include

1. **feature_importance.png**
   Caption: "Figure X: Random Forest feature importance analysis showing TCP network features as the strongest indicators of malicious behavior. Blue bars highlight network-related features."

2. **tcp_comparison.png**
   Caption: "Figure X: Comparison of TCP network activity between benign (green) and malicious (red) packages. Malicious packages show 4.5x higher state transitions and 3.7x more remote IP connections."

3. **dataset_composition.png**
   Caption: "Figure X: Current dataset composition showing class imbalance (9 benign vs 1 malicious samples) and package distribution."

4. **feature_heatmap.png**
   Caption: "Figure X: Feature value heatmap comparing average values for benign and malicious packages across top 12 discriminating features."

5. **data_quality.png**
   Caption: "Figure X: Data quality issues identified during analysis. The C1 bug (write_processes always 0) affects all current samples and will be resolved in the next data capture."

### Report Template Sections

Please create the report template with these sections:
1. Abstract (200 words)
2. Introduction
3. Problem Statement (Manikandan is writing)
4. System Architecture (reference dissertation)
5. Phase 3 Progress
   - 5.1 Data Collection Improvements
   - 5.2 ML Analysis Results (I wrote this - report_ml_section.md)
   - 5.3 Bug Fixes and Enhancements
6. Results and Discussion
7. Limitations and Future Work
8. Conclusion
9. References

### Data Tables to Create

From my output files (in ml_analysis/outputs/):
- sessions_flattened.csv → Table of all sessions
- feature_discriminability.csv → Top 10 features table

Let me know if you have questions!

Karthik
```

---



## Summary Checklist

- [ ] Send Aniruddha message and get confirmation
- [ ] Send Manikandan message and confirm he's started
- [ ] Send Komal message and share the figures folder
- [ ] Follow up tomorrow for progress check

---

*Generated: August 24, 2026*