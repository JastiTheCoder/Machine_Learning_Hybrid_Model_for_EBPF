"""
QUT-DV25 Feature Extractor

This module extracts the exact 36 features used in the QUT-DV25 dataset paper.
The features are organized into 6 categories:
1. Filetop Traces (5 features)
2. Install Traces (3 features)
3. Opensnoop Traces (7 features)
4. TCP Traces (5 features)
5. SysCall Traces (6 features)
6. Pattern Traces (10 features)

Total: 36 features
"""

import os
import sys
import numpy as np
from typing import Dict, List, Any, Tuple, Optional
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import re
import logging
import json

# Add project root
from pathlib import Path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

logger = logging.getLogger(__name__)

# Define the exact 36 QUT features
QUT_FEATURE_NAMES = [
    # Filetop Traces (5)
    'Read_Processes',
    'Write_Processes', 
    'Read_Data_Transfer',
    'Write_Data_Transfer',
    'File_Access_Processes',
    
    # Install Traces (3)
    'Total_Dependencies',
    'Direct_Dependencies',
    'Indirect_Dependencies',
    
    # Opensnoop Traces (7)
    'Root_DIR_Access',
    'Temp_DIR_Access',
    'Home_DIR_Access',
    'User_DIR_Access',
    'Sys_DIR_Access',
    'Etc_DIR_Access',
    'Other_DIR_Access',
    
    # TCP Traces (5)
    'State_Transition',
    'Local_IPs_Access',
    'Remote_IPs_Access',
    'Local_Port_Access',
    'Remote_Port_Access',
    
    # SysCall Traces (6)
    'IO_Operations',
    'File_Operations',
    'Network_Operations',
    'Time_Operations',
    'Security_Operations',
    'Process_Operations',
    
    # Pattern Traces (10)
    'Pattern_1',  # File metadata retrieval
    'Pattern_2',  # Reading data from file
    'Pattern_3',  # Writing data to file
    'Pattern_4',  # Network socket creation
    'Pattern_5',  # Process creation
    'Pattern_6',  # Memory mapping
    'Pattern_7',  # File descriptor management
    'Pattern_8',  # Inter-process communication
    'Pattern_9',  # File locking
    'Pattern_10', # Error handling
]


@dataclass
class QUTFeatureSet:
    """Container for QUT-style extracted features."""
    package_name: str
    label: int
    
    # All 36 numeric features
    numeric_features: Dict[str, float] = field(default_factory=dict)
    
    # Sequence features for LSTM (optional)
    syscall_sequence: List[str] = field(default_factory=list)
    
    def to_flat_dict(self) -> Dict[str, Any]:
        """Flatten all features to a single dictionary."""
        result = {
            'package_name': self.package_name,
            'label': self.label,
        }
        result.update(self.numeric_features)
        return result
    
    def to_feature_vector(self) -> np.ndarray:
        """Convert to numpy array in consistent order."""
        return np.array([self.numeric_features.get(f, 0.0) for f in QUT_FEATURE_NAMES])


class QUTFeatureExtractor:
    """
    Feature extractor that extracts exactly the 36 features from QUT-DV25 paper.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize feature extractor."""
        self.config = config or {}
        self.feature_names = QUT_FEATURE_NAMES
        
        # Syscall category mappings based on QUT paper
        self.io_syscalls = {'ioctl', 'poll', 'select', 'readv', 'writev', 'preadv', 'pwritev',
                           'epoll_create', 'epoll_ctl', 'epoll_wait', 'ppoll', 'pselect6'}
        
        self.file_syscalls = {'open', 'openat', 'creat', 'close', 'read', 'write', 'lseek',
                              'pread64', 'pwrite64', 'stat', 'fstat', 'lstat', 'newfstatat',
                              'access', 'faccessat', 'truncate', 'ftruncate', 'rename', 'renameat',
                              'mkdir', 'mkdirat', 'rmdir', 'unlink', 'unlinkat', 'link', 'linkat',
                              'symlink', 'symlinkat', 'readlink', 'readlinkat', 'chmod', 'fchmod',
                              'chown', 'fchown', 'lchown', 'utime', 'utimes', 'futimesat',
                              'getdents', 'getdents64', 'fsync', 'fdatasync', 'flock'}
        
        self.network_syscalls = {'socket', 'connect', 'accept', 'accept4', 'bind', 'listen',
                                 'send', 'sendto', 'sendmsg', 'recv', 'recvfrom', 'recvmsg',
                                 'shutdown', 'getsockname', 'getpeername', 'setsockopt',
                                 'getsockopt', 'socketpair'}
        
        self.time_syscalls = {'clock_gettime', 'clock_settime', 'clock_getres', 'time',
                              'gettimeofday', 'settimeofday', 'timer_create', 'timer_settime',
                              'timer_gettime', 'timer_getoverrun', 'timer_delete', 'nanosleep',
                              'clock_nanosleep', 'alarm', 'setitimer', 'getitimer'}
        
        self.security_syscalls = {'getuid', 'geteuid', 'getgid', 'getegid', 'setuid', 'setgid',
                                  'setreuid', 'setregid', 'getresuid', 'getresgid', 'setresuid',
                                  'setresgid', 'setfsuid', 'setfsgid', 'capget', 'capset',
                                  'prctl', 'seccomp'}
        
        self.process_syscalls = {'fork', 'vfork', 'clone', 'clone3', 'execve', 'execveat',
                                 'exit', 'exit_group', 'wait4', 'waitid', 'kill', 'tkill',
                                 'tgkill', 'getpid', 'getppid', 'gettid', 'getpgid', 'setpgid',
                                 'setsid', 'getsid'}
        
        # Pattern detection patterns (syscall sequences)
        self.patterns = {
            'Pattern_1': ['newfstatat', 'openat', 'fstat'],  # File metadata
            'Pattern_2': ['read', 'pread64', 'lseek'],       # File reading
            'Pattern_3': ['write', 'pwrite64', 'fsync'],     # File writing
            'Pattern_4': ['socket', 'bind', 'listen'],       # Socket creation
            'Pattern_5': ['fork', 'execve', 'wait4'],        # Process creation
            'Pattern_6': ['mmap', 'mprotect', 'munmap'],     # Memory mapping
            'Pattern_7': ['dup', 'dup2', 'close'],           # FD management
            'Pattern_8': ['pipe', 'write', 'read'],          # IPC
            'Pattern_9': ['fcntl', 'flock', 'close'],        # File locking
            'Pattern_10': ['open', 'read'],                  # Error handling (with ENOENT)
        }

    def extract_features(self, parsed_trace: Dict) -> QUTFeatureSet:
        """
        Extract all 36 QUT features from a parsed trace.
        
        Args:
            parsed_trace: Dictionary containing parsed trace data
            
        Returns:
            QUTFeatureSet object with all 36 features
        """
        features = QUTFeatureSet(
            package_name=parsed_trace.get('package_name', 'unknown'),
            label=parsed_trace.get('label', 0)
        )
        
        # Initialize all features to 0
        for name in QUT_FEATURE_NAMES:
            features.numeric_features[name] = 0.0
        
        # Extract each feature category
        file_ops = parsed_trace.get('file_operations', [])
        net_ops = parsed_trace.get('network_operations', [])
        proc_info = parsed_trace.get('process_info', [])
        patterns = parsed_trace.get('patterns', {})
        
        # 1. Filetop features
        self._extract_filetop_features(file_ops, features)
        
        # 2. Install features
        self._extract_install_features(patterns, features)
        
        # 3. Opensnoop features (directory access)
        self._extract_opensnoop_features(file_ops, patterns, features)
        
        # 4. TCP features
        self._extract_tcp_features(net_ops, features)
        
        # 5. SysCall category features
        self._extract_syscall_features(patterns, features)
        
        # 6. Pattern features
        self._extract_pattern_features(patterns, features)
        
        # Build sequence for LSTM
        self._build_sequences(file_ops, net_ops, patterns, features)
        
        return features

    def _extract_filetop_features(self, file_ops: List[Dict], features: QUTFeatureSet) -> None:
        """Extract Filetop trace features (5 features)."""
        
        read_processes = set()
        write_processes = set()
        all_processes = set()
        read_bytes = 0
        write_bytes = 0
        
        for op in file_ops:
            process = op.get('process_name', op.get('comm', ''))
            operation = op.get('operation', '').lower()
            bytes_count = op.get('bytes_count', 0)
            
            if process:
                all_processes.add(process)
                
                if operation in ['read', 'pread', 'readv']:
                    read_processes.add(process)
                    read_bytes += bytes_count
                elif operation in ['write', 'pwrite', 'writev']:
                    write_processes.add(process)
                    write_bytes += bytes_count
        
        features.numeric_features['Read_Processes'] = len(read_processes)
        features.numeric_features['Write_Processes'] = len(write_processes)
        features.numeric_features['Read_Data_Transfer'] = read_bytes
        features.numeric_features['Write_Data_Transfer'] = write_bytes
        features.numeric_features['File_Access_Processes'] = len(all_processes)

    def _extract_install_features(self, patterns: Dict, features: QUTFeatureSet) -> None:
        """Extract Install trace features (3 features)."""
        
        install_meta = patterns.get('installation', {})
        
        # Get dependency information
        total_deps = install_meta.get('total_packages', 0)
        dependencies = install_meta.get('dependencies', [])
        
        # Estimate direct vs indirect (if not available, use heuristics)
        direct_deps = len(dependencies) if dependencies else 0
        indirect_deps = max(0, total_deps - direct_deps - 1)  # -1 for the package itself
        
        features.numeric_features['Total_Dependencies'] = total_deps
        features.numeric_features['Direct_Dependencies'] = direct_deps
        features.numeric_features['Indirect_Dependencies'] = indirect_deps

    def _extract_opensnoop_features(self, file_ops: List[Dict], patterns: Dict, 
                                    features: QUTFeatureSet) -> None:
        """Extract Opensnoop trace features (7 features) - directory access patterns."""
        
        # Count directory accesses by type
        dir_counts = {
            'root': 0,    # / or /root
            'temp': 0,    # /tmp, /var/tmp
            'home': 0,    # /home
            'user': 0,    # /usr
            'sys': 0,     # /sys, /proc
            'etc': 0,     # /etc
            'other': 0    # everything else
        }
        
        # Get paths from file operations
        paths = set()
        for op in file_ops:
            filepath = op.get('filepath', '')
            if filepath:
                paths.add(filepath)
        
        # Also get paths from strace patterns
        all_paths = patterns.get('all_paths_accessed', [])
        paths.update(all_paths)
        
        # Classify each path
        for path in paths:
            if not path:
                continue
            path_lower = path.lower()
            
            if path_lower.startswith('/root') or path_lower == '/':
                dir_counts['root'] += 1
            elif '/tmp' in path_lower or '/var/tmp' in path_lower:
                dir_counts['temp'] += 1
            elif path_lower.startswith('/home'):
                dir_counts['home'] += 1
            elif path_lower.startswith('/usr'):
                dir_counts['user'] += 1
            elif path_lower.startswith('/sys') or path_lower.startswith('/proc'):
                dir_counts['sys'] += 1
            elif path_lower.startswith('/etc'):
                dir_counts['etc'] += 1
            else:
                dir_counts['other'] += 1
        
        features.numeric_features['Root_DIR_Access'] = dir_counts['root']
        features.numeric_features['Temp_DIR_Access'] = dir_counts['temp']
        features.numeric_features['Home_DIR_Access'] = dir_counts['home']
        features.numeric_features['User_DIR_Access'] = dir_counts['user']
        features.numeric_features['Sys_DIR_Access'] = dir_counts['sys']
        features.numeric_features['Etc_DIR_Access'] = dir_counts['etc']
        features.numeric_features['Other_DIR_Access'] = dir_counts['other']

    def _extract_tcp_features(self, net_ops: List[Dict], features: QUTFeatureSet) -> None:
        """Extract TCP trace features (5 features)."""
        
        local_ips = set()
        remote_ips = set()
        local_ports = set()
        remote_ports = set()
        state_transitions = 0
        
        localhost_indicators = ['127.0.0.1', 'localhost', '::1', '0.0.0.0']
        
        for op in net_ops:
            # Get source/destination info
            src_ip = op.get('src_ip', '')
            dst_ip = op.get('dst_ip', '')
            src_port = op.get('src_port', 0)
            dst_port = op.get('dst_port', 0)
            
            # Classify IPs
            if src_ip:
                if any(local in src_ip for local in localhost_indicators):
                    local_ips.add(src_ip)
                else:
                    remote_ips.add(src_ip)
            
            if dst_ip:
                if any(local in dst_ip for local in localhost_indicators):
                    local_ips.add(dst_ip)
                else:
                    remote_ips.add(dst_ip)
            
            # Track ports
            if src_port:
                local_ports.add(src_port)
            if dst_port:
                remote_ports.add(dst_port)
            
            # Count state transitions (each operation is a transition)
            state_transitions += 1
        
        features.numeric_features['State_Transition'] = state_transitions
        features.numeric_features['Local_IPs_Access'] = len(local_ips)
        features.numeric_features['Remote_IPs_Access'] = len(remote_ips)
        features.numeric_features['Local_Port_Access'] = len(local_ports)
        features.numeric_features['Remote_Port_Access'] = len(remote_ports)

    def _extract_syscall_features(self, patterns: Dict, features: QUTFeatureSet) -> None:
        """Extract SysCall category features (6 features)."""
        
        syscall_counts = patterns.get('syscall_counts', {})
        
        # Aggregate syscalls by category
        io_ops = sum(syscall_counts.get(sc, 0) for sc in self.io_syscalls)
        file_ops = sum(syscall_counts.get(sc, 0) for sc in self.file_syscalls)
        network_ops = sum(syscall_counts.get(sc, 0) for sc in self.network_syscalls)
        time_ops = sum(syscall_counts.get(sc, 0) for sc in self.time_syscalls)
        security_ops = sum(syscall_counts.get(sc, 0) for sc in self.security_syscalls)
        process_ops = sum(syscall_counts.get(sc, 0) for sc in self.process_syscalls)
        
        features.numeric_features['IO_Operations'] = io_ops
        features.numeric_features['File_Operations'] = file_ops
        features.numeric_features['Network_Operations'] = network_ops
        features.numeric_features['Time_Operations'] = time_ops
        features.numeric_features['Security_Operations'] = security_ops
        features.numeric_features['Process_Operations'] = process_ops

    def _extract_pattern_features(self, patterns: Dict, features: QUTFeatureSet) -> None:
        """Extract Pattern trace features (10 features)."""
        
        syscall_counts = patterns.get('syscall_counts', {})
        
        # Detect patterns based on syscall presence and frequency
        # Pattern detection is heuristic - we look for co-occurrence of related syscalls
        
        # Pattern 1: File metadata retrieval (newfstatat→openat→fstat)
        p1_syscalls = ['newfstatat', 'openat', 'fstat', 'stat', 'lstat']
        features.numeric_features['Pattern_1'] = min(
            sum(syscall_counts.get(sc, 0) for sc in p1_syscalls) / 100.0, 100.0
        )
        
        # Pattern 2: Reading data from file (read→pread64→lseek)
        p2_syscalls = ['read', 'pread64', 'lseek', 'readv']
        features.numeric_features['Pattern_2'] = min(
            sum(syscall_counts.get(sc, 0) for sc in p2_syscalls) / 100.0, 100.0
        )
        
        # Pattern 3: Writing data to file (write→pwrite64→fsync)
        p3_syscalls = ['write', 'pwrite64', 'fsync', 'writev', 'fdatasync']
        features.numeric_features['Pattern_3'] = min(
            sum(syscall_counts.get(sc, 0) for sc in p3_syscalls) / 100.0, 100.0
        )
        
        # Pattern 4: Network socket creation (socket→bind→listen)
        p4_syscalls = ['socket', 'bind', 'listen', 'accept', 'connect']
        features.numeric_features['Pattern_4'] = min(
            sum(syscall_counts.get(sc, 0) for sc in p4_syscalls) / 10.0, 100.0
        )
        
        # Pattern 5: Process creation (fork→execve→wait4)
        p5_syscalls = ['fork', 'vfork', 'clone', 'clone3', 'execve', 'wait4', 'waitid']
        features.numeric_features['Pattern_5'] = min(
            sum(syscall_counts.get(sc, 0) for sc in p5_syscalls) / 10.0, 100.0
        )
        
        # Pattern 6: Memory mapping (mmap→mprotect→munmap)
        p6_syscalls = ['mmap', 'mprotect', 'munmap', 'mremap', 'madvise']
        features.numeric_features['Pattern_6'] = min(
            sum(syscall_counts.get(sc, 0) for sc in p6_syscalls) / 50.0, 100.0
        )
        
        # Pattern 7: File descriptor management (dup→dup2→close)
        p7_syscalls = ['dup', 'dup2', 'dup3', 'close']
        features.numeric_features['Pattern_7'] = min(
            sum(syscall_counts.get(sc, 0) for sc in p7_syscalls) / 50.0, 100.0
        )
        
        # Pattern 8: Inter-process communication (pipe→write→read)
        p8_syscalls = ['pipe', 'pipe2', 'write', 'read']
        features.numeric_features['Pattern_8'] = min(
            sum(syscall_counts.get(sc, 0) for sc in p8_syscalls) / 100.0, 100.0
        )
        
        # Pattern 9: File locking (fcntl→flock→close)
        p9_syscalls = ['fcntl', 'flock']
        features.numeric_features['Pattern_9'] = min(
            sum(syscall_counts.get(sc, 0) for sc in p9_syscalls) / 10.0, 100.0
        )
        
        # Pattern 10: Error handling (based on error count from strace)
        strace_data = patterns.get('strace', [])
        total_errors = sum(s.get('return_errors', 0) for s in strace_data)
        features.numeric_features['Pattern_10'] = min(total_errors / 10.0, 100.0)

    def _build_sequences(self, file_ops: List[Dict], net_ops: List[Dict],
                        patterns: Dict, features: QUTFeatureSet) -> None:
        """Build syscall sequence for LSTM models."""
        
        # Build sequence from syscall counts
        syscall_counts = patterns.get('syscall_counts', {})
        
        # Create sequence based on most common syscalls
        for syscall, count in sorted(syscall_counts.items(), key=lambda x: -x[1])[:100]:
            for _ in range(min(count, 10)):  # Repeat up to 10 times
                features.syscall_sequence.append(syscall)
        
        # Add file operations
        for op in file_ops[:200]:
            op_type = op.get('operation', 'unknown')
            features.syscall_sequence.append(f"file_{op_type}")
        
        # Add network operations
        for op in net_ops[:50]:
            op_type = op.get('operation', 'unknown')
            features.syscall_sequence.append(f"net_{op_type}")
        
        # Limit sequence length
        features.syscall_sequence = features.syscall_sequence[:500]

    def get_feature_names(self) -> List[str]:
        """Get list of all 36 QUT feature names."""
        return QUT_FEATURE_NAMES.copy()


def extract_qut_features_from_parsed_data(
    benign_data: List[Dict],
    malicious_data: List[Dict]
) -> Tuple[np.ndarray, np.ndarray, List[str], List[Dict]]:
    """
    Extract QUT features from pre-parsed trace data.
    
    Returns:
        X: Feature matrix
        y: Labels
        feature_names: List of feature names
        all_features: List of feature dictionaries
    """
    extractor = QUTFeatureExtractor()
    all_features = []
    
    # Extract features from benign samples
    for sample in benign_data:
        sample['label'] = 0
        features = extractor.extract_features(sample)
        all_features.append(features)
    
    # Extract features from malicious samples
    for sample in malicious_data:
        sample['label'] = 1
        features = extractor.extract_features(sample)
        all_features.append(features)
    
    # Convert to arrays
    X = np.array([f.to_feature_vector() for f in all_features])
    y = np.array([f.label for f in all_features])
    
    return X, y, extractor.get_feature_names(), all_features


if __name__ == "__main__":
    # Test the extractor
    print(f"QUT Feature Extractor - {len(QUT_FEATURE_NAMES)} features")
    print("\nFeature list:")
    for i, name in enumerate(QUT_FEATURE_NAMES, 1):
        print(f"  {i:2d}. {name}")
