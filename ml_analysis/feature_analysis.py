"""
Feature Discriminability Analysis for eBPF Session Data
========================================================
This script analyzes which features best distinguish between benign and malicious packages.

Created for Phase 3 Progress Report
"""

import json
import os
import pandas as pd
import numpy as np
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

SESSIONS_DIR = Path(__file__).parent.parent / "sessions"
OUTPUT_DIR = Path(__file__).parent / "outputs"

# Label mapping: package name patterns -> labels
# Malicious = our test attack packages
# Benign = real npm packages and our benign test
LABEL_RULES = {
    # Benign packages
    "lodash": "benign",
    "benign-test": "benign",
    "underscore": "benign",
    "moment": "benign",
    "chalk": "benign",
    "axios": "benign",
    "uuid": "benign",
    "dotenv": "benign",
    "debug": "benign",
    # Malicious test packages
    "suspicious-test": "malicious",
    "env-stealer": "malicious",
    "ssh-reader": "malicious",
    "reverse-shell": "malicious",
    "persistence-test": "malicious",
}

# ============================================================================
# DATA LOADING
# ============================================================================

def load_session(filepath: Path) -> dict:
    """Load a single session JSON file."""
    with open(filepath, 'r') as f:
        return json.load(f)

def flatten_session(session: dict) -> dict:
    """Flatten nested session data into a single-level dictionary."""
    flat = {
        "session_id": session.get("session_id"),
        "package_name": session.get("package_name"),
    }
    
    # Filetop features
    filetop = session.get("filetop", {})
    flat["ft_read_processes"] = filetop.get("read_processes", 0)
    flat["ft_write_processes"] = filetop.get("write_processes", 0)
    flat["ft_read_data_kb"] = filetop.get("read_data_transfer_kb", 0)
    flat["ft_write_data_kb"] = filetop.get("write_data_transfer_kb", 0)
    flat["ft_file_access_processes"] = filetop.get("file_access_processes", 0)
    
    # Install features
    install = session.get("install", {})
    flat["inst_total_deps"] = install.get("total_dependencies", 0)
    flat["inst_direct_deps"] = install.get("direct_dependencies", 0)
    flat["inst_indirect_deps"] = install.get("indirect_dependencies", 0)
    
    # Opensnoop features (file access by directory)
    opensnoop = session.get("opensnoop", {})
    flat["os_etc_dir"] = opensnoop.get("etc_dir_access", 0)
    flat["os_home_dir"] = opensnoop.get("home_dir_access", 0)
    flat["os_other_dir"] = opensnoop.get("other_dir_access", 0)
    flat["os_root_dir"] = opensnoop.get("root_dir_access", 0)
    flat["os_sys_dir"] = opensnoop.get("sys_dir_access", 0)
    flat["os_temp_dir"] = opensnoop.get("temp_dir_access", 0)
    flat["os_user_dir"] = opensnoop.get("user_dir_access", 0)
    flat["os_ssh_aws_wallet"] = opensnoop.get("ssh_aws_wallet_access", 0)
    
    # TCP features (network activity)
    tcp = session.get("tcp", {})
    # Handle both camelCase and snake_case (different versions of monitor)
    flat["tcp_state_transitions"] = tcp.get("state_transitions", tcp.get("StateTransitions", 0))
    flat["tcp_local_ips"] = tcp.get("local_ips", tcp.get("LocalIPs", 0))
    flat["tcp_remote_ips"] = tcp.get("remote_ips", tcp.get("RemoteIPs", 0))
    flat["tcp_local_ports"] = tcp.get("local_ports", tcp.get("LocalPorts", 0))
    flat["tcp_remote_ports"] = tcp.get("remote_ports", tcp.get("RemotePorts", 0))
    
    # Syscall features
    syscalls = session.get("syscalls", {})
    flat["sc_io_ops"] = syscalls.get("io_ops", 0)
    flat["sc_file_ops"] = syscalls.get("file_ops", 0)
    flat["sc_network_ops"] = syscalls.get("network_ops", 0)
    flat["sc_time_ops"] = syscalls.get("time_ops", 0)
    flat["sc_security_ops"] = syscalls.get("security_ops", 0)
    flat["sc_process_ops"] = syscalls.get("process_ops", 0)
    flat["sc_unknown_ops"] = syscalls.get("unknown_ops", 0)
    
    # Pattern features
    patterns = session.get("patterns", {})
    flat["pat_file_metadata"] = patterns.get("p1_file_metadata", 0)
    flat["pat_read_data"] = patterns.get("p2_read_data", 0)
    flat["pat_write_data"] = patterns.get("p3_write_data", 0)
    flat["pat_socket_create"] = patterns.get("p4_socket_create", 0)
    flat["pat_process_create"] = patterns.get("p5_process_create", 0)
    flat["pat_memory_map"] = patterns.get("p6_memory_map", 0)
    flat["pat_fd_manage"] = patterns.get("p7_fd_manage", 0)
    flat["pat_ipc"] = patterns.get("p8_ipc", 0)
    flat["pat_file_lock"] = patterns.get("p9_file_lock", 0)
    flat["pat_error_handle"] = patterns.get("p10_error_handle", 0)
    
    return flat

def assign_label(package_name: str, filename: str = "", verdict_level: str = None) -> str:
    """Assign label based on package name, filename, or verdict.
    
    Priority:
    1. If verdict_level is provided (from eBPF verdict engine), use it
    2. Otherwise, check package_name against LABEL_RULES
    3. Finally, check filename against LABEL_RULES
    """
    # If we have a verdict from the eBPF monitor, use it
    if verdict_level:
        if verdict_level == "malicious":
            return "malicious"
        elif verdict_level in ["benign", "suspicious"]:
            return "benign"  # Treat suspicious as benign for ML training
    
    # Check package name
    package_lower = package_name.lower()
    for pattern, label in LABEL_RULES.items():
        if pattern in package_lower:
            return label
    
    # Check filename (for cases where package_name is "unknown")
    filename_lower = filename.lower()
    for pattern, label in LABEL_RULES.items():
        if pattern in filename_lower:
            return label
    
    return "unknown"

def load_all_sessions() -> pd.DataFrame:
    """Load all session files and return as DataFrame."""
    sessions = []
    
    if not SESSIONS_DIR.exists():
        print(f"ERROR: Sessions directory not found: {SESSIONS_DIR}")
        return pd.DataFrame()
    
    json_files = list(SESSIONS_DIR.glob("*.json"))
    print(f"Found {len(json_files)} session files in {SESSIONS_DIR}")
    
    for filepath in json_files:
        try:
            session = load_session(filepath)
            flat = flatten_session(session)
            
            # Extract verdict level if available (from Aniruddha's verdict scoring engine)
            verdict = session.get("verdict", {})
            verdict_level = verdict.get("level", None)
            
            # Use filename for package name if it's "unknown"
            if flat["package_name"] == "unknown":
                # Extract package name from filename like "npm-1787577556_reverse-shell-test.json"
                parts = filepath.stem.split("_", 1)
                if len(parts) > 1:
                    flat["package_name"] = parts[1]
            
            flat["label"] = assign_label(flat["package_name"], filepath.name, verdict_level)
            flat["verdict_score"] = verdict.get("score", 0)
            flat["verdict_level"] = verdict_level or "none"
            sessions.append(flat)
        except Exception as e:
            print(f"  Warning: Failed to load {filepath.name}: {e}")
    
    df = pd.DataFrame(sessions)
    return df

# ============================================================================
# FEATURE ANALYSIS
# ============================================================================

def get_feature_columns(df: pd.DataFrame) -> list:
    """Get list of numeric feature columns (excluding metadata)."""
    exclude = ["session_id", "package_name", "label", "verdict_score", "verdict_level"]
    return [col for col in df.columns if col not in exclude]

def calculate_discriminability(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate how well each feature separates benign from malicious samples.
    
    Returns DataFrame with:
    - Feature name
    - Mean value for benign samples
    - Mean value for malicious samples
    - Difference (malicious - benign)
    - Separability score (Cohen's d effect size)
    """
    features = get_feature_columns(df)
    
    benign = df[df["label"] == "benign"]
    malicious = df[df["label"] == "malicious"]
    
    results = []
    
    for feat in features:
        benign_vals = benign[feat].values
        mal_vals = malicious[feat].values
        
        benign_mean = np.mean(benign_vals) if len(benign_vals) > 0 else 0
        mal_mean = np.mean(mal_vals) if len(mal_vals) > 0 else 0
        
        benign_std = np.std(benign_vals) if len(benign_vals) > 0 else 0
        mal_std = np.std(mal_vals) if len(mal_vals) > 0 else 0
        
        # Pooled standard deviation
        pooled_std = np.sqrt((benign_std**2 + mal_std**2) / 2) if (benign_std > 0 or mal_std > 0) else 1
        
        # Cohen's d effect size (how many standard deviations apart are the means)
        cohens_d = abs(mal_mean - benign_mean) / pooled_std if pooled_std > 0 else 0
        
        results.append({
            "feature": feat,
            "benign_mean": benign_mean,
            "malicious_mean": mal_mean,
            "difference": mal_mean - benign_mean,
            "cohens_d": cohens_d,
            "discriminability": "HIGH" if cohens_d > 0.8 else ("MEDIUM" if cohens_d > 0.5 else "LOW")
        })
    
    result_df = pd.DataFrame(results)
    return result_df.sort_values("cohens_d", ascending=False)

def print_analysis_report(df: pd.DataFrame, disc_df: pd.DataFrame):
    """Print a human-readable analysis report."""
    
    print("\n" + "="*70)
    print("FEATURE DISCRIMINABILITY ANALYSIS REPORT")
    print("="*70)
    
    # Dataset summary
    print("\n## DATASET SUMMARY")
    print("-"*40)
    print(f"Total sessions: {len(df)}")
    label_counts = df["label"].value_counts()
    for label, count in label_counts.items():
        print(f"  - {label}: {count}")
    
    # Package breakdown
    print("\nPackages analyzed:")
    for pkg in df["package_name"].unique():
        label = df[df["package_name"] == pkg]["label"].iloc[0]
        count = len(df[df["package_name"] == pkg])
        print(f"  - {pkg}: {count} sessions ({label})")
    
    # Known data quality issues
    print("\n## DATA QUALITY NOTES")
    print("-"*40)
    if (df["ft_write_processes"] == 0).all():
        print("WARNING: write_processes is 0 for all sessions!")
        print("  This is the C1 bug identified in AUDIT.md.")
        print("  Aniruddha's fix will correct this in new captures.")
    
    # Top discriminating features
    print("\n## TOP DISCRIMINATING FEATURES")
    print("-"*40)
    print("(Higher Cohen's d = better at separating benign from malicious)\n")
    
    high_disc = disc_df[disc_df["discriminability"] == "HIGH"]
    if len(high_disc) > 0:
        print("HIGH DISCRIMINABILITY (Cohen's d > 0.8):")
        for _, row in high_disc.iterrows():
            direction = "higher in malicious" if row["difference"] > 0 else "lower in malicious"
            print(f"  * {row['feature']}: d={row['cohens_d']:.2f} ({direction})")
    else:
        print("No features with HIGH discriminability found.")
    
    print()
    medium_disc = disc_df[disc_df["discriminability"] == "MEDIUM"]
    if len(medium_disc) > 0:
        print("MEDIUM DISCRIMINABILITY (Cohen's d 0.5-0.8):")
        for _, row in medium_disc.iterrows():
            direction = "higher in malicious" if row["difference"] > 0 else "lower in malicious"
            print(f"  * {row['feature']}: d={row['cohens_d']:.2f} ({direction})")
    
    # Problem features (always zero or no variance)
    print("\n## PROBLEM FEATURES")
    print("-"*40)
    zero_variance = [col for col in get_feature_columns(df) if df[col].std() == 0]
    if zero_variance:
        print("Features with zero variance (no useful signal):")
        for feat in zero_variance:
            print(f"  - {feat}")
    else:
        print("All features have some variance.")
    
    # Summary statistics table
    print("\n## DETAILED FEATURE STATISTICS")
    print("-"*40)
    print(f"{'Feature':<25} {'Benign':>10} {'Malicious':>10} {'Cohen d':>10} {'Rating':>10}")
    print("-"*65)
    for _, row in disc_df.head(15).iterrows():
        print(f"{row['feature']:<25} {row['benign_mean']:>10.2f} {row['malicious_mean']:>10.2f} {row['cohens_d']:>10.2f} {row['discriminability']:>10}")
    
    # Recommendations
    print("\n## RECOMMENDATIONS FOR ML MODEL")
    print("-"*40)
    print("1. Focus on TCP features - they show the clearest signal for malicious behavior")
    print("2. The ft_write_processes bug means file write detection is currently broken")
    print("3. Need more malicious samples for robust training")
    print("4. Consider combining features (e.g., total network activity)")
    
    return disc_df

# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point."""
    print("Loading session data...")
    df = load_all_sessions()
    
    if len(df) == 0:
        print("ERROR: No sessions loaded!")
        return
    
    # Filter out unknown labels
    df_labeled = df[df["label"] != "unknown"]
    if len(df_labeled) == 0:
        print("ERROR: No labeled sessions found!")
        return
    
    print(f"Loaded {len(df_labeled)} labeled sessions")
    
    # Calculate discriminability
    disc_df = calculate_discriminability(df_labeled)
    
    # Print report
    print_analysis_report(df_labeled, disc_df)
    
    # Save outputs
    OUTPUT_DIR.mkdir(exist_ok=True)
    
    df_labeled.to_csv(OUTPUT_DIR / "sessions_flattened.csv", index=False)
    disc_df.to_csv(OUTPUT_DIR / "feature_discriminability.csv", index=False)
    
    print(f"\n## OUTPUT FILES")
    print(f"  - {OUTPUT_DIR / 'sessions_flattened.csv'}")
    print(f"  - {OUTPUT_DIR / 'feature_discriminability.csv'}")
    
    return df_labeled, disc_df

if __name__ == "__main__":
    main()
