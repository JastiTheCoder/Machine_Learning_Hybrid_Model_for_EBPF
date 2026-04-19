"""
Utility functions for the eBPF Malware Detection System
"""

import os
import yaml
import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional


def setup_logging(log_dir: str = "logs", name: str = "ebpf_detector") -> logging.Logger:
    """
    Set up logging configuration.
    
    Args:
        log_dir: Directory to store log files
        name: Logger name
        
    Returns:
        Configured logger instance
    """
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"{name}_{timestamp}.log")
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    # File handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    
    return logger


def load_config(config_path: str = "configs/config.yaml") -> Dict[str, Any]:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to the YAML configuration file
        
    Returns:
        Configuration dictionary
    """
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    return config


def save_json(data: Any, filepath: str) -> None:
    """Save data to JSON file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)


def load_json(filepath: str) -> Any:
    """Load data from JSON file."""
    with open(filepath, 'r') as f:
        return json.load(f)


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent.parent


def ensure_dir(dir_path: str) -> None:
    """Ensure directory exists, create if not."""
    os.makedirs(dir_path, exist_ok=True)


def list_trace_files(
    directory: str, 
    trace_type: str,
    extension: str = ".txt"
) -> List[str]:
    """
    List all trace files of a specific type in a directory.
    
    Args:
        directory: Base directory to search
        trace_type: Type of trace (filetop, opensnoop, tcp, etc.)
        extension: File extension to look for
        
    Returns:
        List of file paths
    """
    trace_dir = os.path.join(directory, f"QUT-DV25_{trace_type.capitalize()}_Traces")
    if not os.path.exists(trace_dir):
        # Try alternative naming
        trace_dir = os.path.join(directory, f"QUT-DV25_{trace_type}_Traces")
    
    if not os.path.exists(trace_dir):
        return []
    
    files = []
    for f in os.listdir(trace_dir):
        if f.endswith(extension):
            files.append(os.path.join(trace_dir, f))
    
    return sorted(files)


def extract_package_name(filepath: str) -> str:
    """
    Extract package name from trace file path.
    
    Example: 'aiohttp_filetop_trace.txt' -> 'aiohttp'
    """
    filename = os.path.basename(filepath)
    # Remove trace type suffix and extension
    parts = filename.rsplit('_', 2)
    if len(parts) >= 3:
        return parts[0]
    return filename.split('_')[0]


class Timer:
    """Simple timer context manager for profiling."""
    
    def __init__(self, name: str = "Operation"):
        self.name = name
        self.start_time = None
        self.end_time = None
        
    def __enter__(self):
        self.start_time = datetime.now()
        return self
        
    def __exit__(self, *args):
        self.end_time = datetime.now()
        elapsed = (self.end_time - self.start_time).total_seconds()
        print(f"{self.name} completed in {elapsed:.2f} seconds")


# Syscall categories for feature engineering
SYSCALL_CATEGORIES = {
    'file_read': ['read', 'pread64', 'readv', 'preadv'],
    'file_write': ['write', 'pwrite64', 'writev', 'pwritev'],
    'file_open': ['open', 'openat', 'creat'],
    'file_close': ['close'],
    'file_stat': ['stat', 'fstat', 'lstat', 'statx'],
    'file_access': ['access', 'faccessat'],
    'directory': ['mkdir', 'rmdir', 'chdir', 'getcwd', 'getdents'],
    'link': ['link', 'unlink', 'symlink', 'readlink', 'rename'],
    'permission': ['chmod', 'chown', 'fchmod', 'fchown'],
    'memory': ['mmap', 'munmap', 'mprotect', 'brk'],
    'process': ['fork', 'vfork', 'clone', 'execve', 'exit', 'wait4'],
    'network': ['socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv', 'sendto', 'recvfrom'],
    'ipc': ['pipe', 'shmget', 'shmat', 'msgget', 'msgsnd', 'msgrcv'],
    'signal': ['kill', 'signal', 'sigaction', 'sigprocmask'],
    'time': ['time', 'gettimeofday', 'clock_gettime', 'nanosleep'],
}

# Sensitive paths that malware commonly accesses
SENSITIVE_PATHS = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/hosts',
    '/etc/crontab',
    '/etc/sudoers',
    '/.ssh/',
    '/id_rsa',
    '/id_dsa',
    '/known_hosts',
    '/authorized_keys',
    '/proc/self/',
    '/proc/net/',
    '/sys/',
    '/.bashrc',
    '/.bash_profile',
    '/.profile',
    '/.zshrc',
    '/.aws/',
    '/.config/',
    '/cron.d/',
    '/cron.daily/',
    '/init.d/',
    '/systemd/',
]

# Common malware network indicators
SUSPICIOUS_NETWORK = {
    'ports': [4444, 5555, 6666, 1337, 31337, 8080, 8443, 9001, 9050],
    'localhost_indicators': ['127.0.0.1', '0.0.0.0', 'localhost'],
}
