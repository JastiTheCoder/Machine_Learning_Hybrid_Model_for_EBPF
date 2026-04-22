"""
Feature Extraction Module for eBPF Malware Detection

This module extracts meaningful features from parsed trace data:
1. Syscall frequency features
2. File operation features  
3. Network behavior features
4. Process behavior features
5. Temporal/behavioral features
6. N-gram features for sequence models

The features are designed based on known malware behaviors:
- Sensitive file access (credentials, configs)
- Network exfiltration patterns
- Process injection/spawning
- Privilege escalation attempts
"""

import os
import sys
import numpy as np
from typing import Dict, List, Any, Tuple, Optional
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import re
import logging

# Add project root
from pathlib import Path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.utils.helpers import SYSCALL_CATEGORIES, SENSITIVE_PATHS, SUSPICIOUS_NETWORK

logger = logging.getLogger(__name__)


@dataclass
class FeatureSet:
    """Container for extracted features."""
    package_name: str
    label: int
    
    # Numeric features (for tree-based models)
    numeric_features: Dict[str, float] = field(default_factory=dict)
    
    # Categorical features
    categorical_features: Dict[str, str] = field(default_factory=dict)
    
    # Sequence features (for LSTM)
    syscall_sequence: List[str] = field(default_factory=list)
    file_sequence: List[str] = field(default_factory=list)
    
    def to_flat_dict(self) -> Dict[str, Any]:
        """Flatten all features to a single dictionary."""
        result = {
            'package_name': self.package_name,
            'label': self.label,
        }
        result.update(self.numeric_features)
        result.update(self.categorical_features)
        return result


class FeatureExtractor:
    """
    Main feature extractor class.
    
    Extracts a comprehensive set of features from parsed trace data
    suitable for both traditional ML and deep learning models.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize feature extractor.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        
        # Feature name prefixes
        self.SYSCALL_PREFIX = 'syscall_'
        self.FILE_PREFIX = 'file_'
        self.NET_PREFIX = 'net_'
        self.PROC_PREFIX = 'proc_'
        self.TEMP_PREFIX = 'temporal_'
        self.PATTERN_PREFIX = 'pattern_'
        
        # Sensitive paths for detection
        self.sensitive_paths = self.config.get('sensitive_paths', SENSITIVE_PATHS)
        
        # Initialize feature statistics for normalization
        self.feature_stats = {}
    
    def extract_features(self, parsed_trace: Dict) -> FeatureSet:
        """
        Extract all features from a parsed trace.
        
        Args:
            parsed_trace: Dictionary containing parsed trace data
            
        Returns:
            FeatureSet object with all extracted features
        """
        features = FeatureSet(
            package_name=parsed_trace.get('package_name', 'unknown'),
            label=parsed_trace.get('label', 0)
        )
        
        # Extract each feature category
        file_ops = parsed_trace.get('file_operations', [])
        net_ops = parsed_trace.get('network_operations', [])
        proc_info = parsed_trace.get('process_info', [])
        patterns = parsed_trace.get('patterns', {})
        
        # 1. File operation features
        self._extract_file_features(file_ops, features)
        
        # 2. Network features
        self._extract_network_features(net_ops, features)
        
        # 3. Process features
        self._extract_process_features(proc_info, features)
        
        # 4. Pattern/behavioral features
        self._extract_pattern_features(patterns, features)
        
        # 5. Aggregate statistics
        self._extract_aggregate_features(parsed_trace, features)
        
        # 6. Build sequences for LSTM
        self._build_sequences(file_ops, net_ops, features)
        
        return features
    
    def _extract_file_features(
        self, 
        file_ops: List[Dict], 
        features: FeatureSet
    ) -> None:
        """Extract features from file operations."""
        
        # Basic counts
        features.numeric_features[f'{self.FILE_PREFIX}total_ops'] = len(file_ops)
        
        # Count by operation type
        op_counts = Counter(op.get('operation', 'unknown') for op in file_ops)
        features.numeric_features[f'{self.FILE_PREFIX}read_count'] = op_counts.get('read', 0)
        features.numeric_features[f'{self.FILE_PREFIX}write_count'] = op_counts.get('write', 0)
        features.numeric_features[f'{self.FILE_PREFIX}open_count'] = op_counts.get('open', 0)
        
        # Read/write ratio
        total_rw = op_counts.get('read', 0) + op_counts.get('write', 0)
        if total_rw > 0:
            features.numeric_features[f'{self.FILE_PREFIX}write_ratio'] = \
                op_counts.get('write', 0) / total_rw
        else:
            features.numeric_features[f'{self.FILE_PREFIX}write_ratio'] = 0.0
        
        # Unique files accessed
        unique_files = set(op.get('filepath', '') for op in file_ops if op.get('filepath'))
        features.numeric_features[f'{self.FILE_PREFIX}unique_files'] = len(unique_files)
        
        # Bytes transferred
        total_bytes = sum(op.get('bytes_count', 0) for op in file_ops)
        features.numeric_features[f'{self.FILE_PREFIX}total_bytes'] = total_bytes
        
        # Sensitive file access
        sensitive_count = 0
        sensitive_types = defaultdict(int)
        
        for filepath in unique_files:
            filepath_lower = filepath.lower()
            for sensitive_path in self.sensitive_paths:
                if sensitive_path.lower() in filepath_lower:
                    sensitive_count += 1
                    # Categorize sensitive access
                    if 'ssh' in filepath_lower or 'id_rsa' in filepath_lower:
                        sensitive_types['ssh_keys'] += 1
                    elif 'passwd' in filepath_lower or 'shadow' in filepath_lower:
                        sensitive_types['credentials'] += 1
                    elif 'cron' in filepath_lower:
                        sensitive_types['persistence'] += 1
                    elif 'bashrc' in filepath_lower or 'profile' in filepath_lower:
                        sensitive_types['shell_config'] += 1
                    elif 'aws' in filepath_lower or 'config' in filepath_lower:
                        sensitive_types['cloud_creds'] += 1
                    elif 'proc' in filepath_lower:
                        sensitive_types['proc_access'] += 1
                    break
        
        features.numeric_features[f'{self.FILE_PREFIX}sensitive_access_count'] = sensitive_count
        features.numeric_features[f'{self.FILE_PREFIX}sensitive_ssh_keys'] = sensitive_types['ssh_keys']
        features.numeric_features[f'{self.FILE_PREFIX}sensitive_credentials'] = sensitive_types['credentials']
        features.numeric_features[f'{self.FILE_PREFIX}sensitive_persistence'] = sensitive_types['persistence']
        features.numeric_features[f'{self.FILE_PREFIX}sensitive_shell_config'] = sensitive_types['shell_config']
        features.numeric_features[f'{self.FILE_PREFIX}sensitive_cloud_creds'] = sensitive_types['cloud_creds']
        features.numeric_features[f'{self.FILE_PREFIX}sensitive_proc'] = sensitive_types['proc_access']
        
        # File extension analysis
        extensions = Counter()
        for filepath in unique_files:
            ext = os.path.splitext(filepath)[1].lower()
            if ext:
                extensions[ext] += 1
        
        # Suspicious extensions
        suspicious_exts = ['.sh', '.py', '.pyc', '.so', '.bin', '.exe']
        features.numeric_features[f'{self.FILE_PREFIX}script_files'] = \
            sum(extensions.get(ext, 0) for ext in ['.sh', '.py', '.pyc'])
        features.numeric_features[f'{self.FILE_PREFIX}binary_files'] = \
            sum(extensions.get(ext, 0) for ext in ['.so', '.bin', '.exe'])
        
        # Directory depth analysis (deep paths can indicate hiding)
        if unique_files:
            depths = [filepath.count('/') for filepath in unique_files if filepath]
            features.numeric_features[f'{self.FILE_PREFIX}max_path_depth'] = max(depths) if depths else 0
            features.numeric_features[f'{self.FILE_PREFIX}avg_path_depth'] = \
                sum(depths) / len(depths) if depths else 0
        else:
            features.numeric_features[f'{self.FILE_PREFIX}max_path_depth'] = 0
            features.numeric_features[f'{self.FILE_PREFIX}avg_path_depth'] = 0
        
        # Hidden files (starting with .)
        hidden_files = sum(1 for f in unique_files if os.path.basename(f).startswith('.'))
        features.numeric_features[f'{self.FILE_PREFIX}hidden_files'] = hidden_files
        
        # Temp directory access
        temp_access = sum(1 for f in unique_files if '/tmp' in f or '/temp' in f.lower())
        features.numeric_features[f'{self.FILE_PREFIX}temp_access'] = temp_access
    
    def _extract_network_features(
        self, 
        net_ops: List[Dict], 
        features: FeatureSet
    ) -> None:
        """Extract features from network operations."""
        
        # Basic counts
        features.numeric_features[f'{self.NET_PREFIX}total_ops'] = len(net_ops)
        
        if not net_ops:
            # Set all network features to 0 if no network activity
            for key in ['connect_count', 'unique_ips', 'unique_ports', 
                       'suspicious_port_count', 'external_connections',
                       'localhost_connections', 'high_port_count']:
                features.numeric_features[f'{self.NET_PREFIX}{key}'] = 0
            return
        
        # Count by operation type
        op_counts = Counter(op.get('operation', 'unknown') for op in net_ops)
        features.numeric_features[f'{self.NET_PREFIX}connect_count'] = op_counts.get('connect', 0)
        features.numeric_features[f'{self.NET_PREFIX}accept_count'] = op_counts.get('accept', 0)
        
        # Unique IPs and ports
        dst_ips = set(op.get('dst_ip', '') for op in net_ops if op.get('dst_ip'))
        dst_ports = set(op.get('dst_port', 0) for op in net_ops if op.get('dst_port'))
        
        features.numeric_features[f'{self.NET_PREFIX}unique_ips'] = len(dst_ips)
        features.numeric_features[f'{self.NET_PREFIX}unique_ports'] = len(dst_ports)
        
        # Suspicious ports
        suspicious_ports = SUSPICIOUS_NETWORK['ports']
        suspicious_port_count = sum(1 for port in dst_ports if port in suspicious_ports)
        features.numeric_features[f'{self.NET_PREFIX}suspicious_port_count'] = suspicious_port_count
        
        # Localhost vs external connections
        localhost_indicators = SUSPICIOUS_NETWORK['localhost_indicators']
        localhost_count = sum(
            1 for op in net_ops 
            if any(local in str(op.get('dst_ip', '')) for local in localhost_indicators)
        )
        features.numeric_features[f'{self.NET_PREFIX}localhost_connections'] = localhost_count
        features.numeric_features[f'{self.NET_PREFIX}external_connections'] = \
            len(net_ops) - localhost_count
        
        # High port usage (ephemeral ports > 1024)
        high_ports = sum(1 for port in dst_ports if port > 1024)
        features.numeric_features[f'{self.NET_PREFIX}high_port_count'] = high_ports
        
        # Common service ports
        common_ports = {80, 443, 22, 21, 25, 53, 3306, 5432, 6379, 27017}
        common_port_count = sum(1 for port in dst_ports if port in common_ports)
        features.numeric_features[f'{self.NET_PREFIX}common_port_count'] = common_port_count
    
    def _extract_process_features(
        self, 
        proc_info: List[Dict], 
        features: FeatureSet
    ) -> None:
        """Extract features from process information."""
        
        features.numeric_features[f'{self.PROC_PREFIX}total_processes'] = len(proc_info)
        
        if not proc_info:
            features.numeric_features[f'{self.PROC_PREFIX}unique_names'] = 0
            features.numeric_features[f'{self.PROC_PREFIX}max_tree_depth'] = 0
            return
        
        # Unique process names
        proc_names = set(p.get('process_name', '') for p in proc_info if p.get('process_name'))
        features.numeric_features[f'{self.PROC_PREFIX}unique_names'] = len(proc_names)
        
        # Process tree analysis
        pids = {p.get('pid') for p in proc_info if p.get('pid')}
        ppids = {p.get('ppid') for p in proc_info if p.get('ppid')}
        
        # Root processes (no parent in our data)
        root_procs = pids - ppids
        features.numeric_features[f'{self.PROC_PREFIX}root_processes'] = len(root_procs)
        
        # Suspicious process names
        suspicious_names = ['sh', 'bash', 'python', 'perl', 'ruby', 'nc', 'netcat', 
                          'curl', 'wget', 'base64', 'eval']
        suspicious_count = sum(
            1 for name in proc_names 
            if any(s in name.lower() for s in suspicious_names)
        )
        features.numeric_features[f'{self.PROC_PREFIX}suspicious_names'] = suspicious_count
    
    def _extract_pattern_features(
        self, 
        patterns: Dict, 
        features: FeatureSet
    ) -> None:
        """Extract features from behavioral patterns (strace data)."""
        
        if not patterns:
            features.numeric_features[f'{self.PATTERN_PREFIX}raw_line_count'] = 0
            return
        
        # Get syscall counts (from strace parsing)
        syscall_counts = patterns.get('syscall_counts', {})
        
        # Total syscalls
        total_syscalls = sum(syscall_counts.values())
        features.numeric_features[f'{self.PATTERN_PREFIX}total_syscalls'] = total_syscalls
        
        # Individual syscall counts (most important for detection)
        important_syscalls = [
            'openat', 'open', 'read', 'write', 'close',
            'stat', 'fstat', 'lstat', 'newfstatat',
            'execve', 'fork', 'clone', 'vfork',
            'socket', 'connect', 'bind', 'listen',
            'mmap', 'mprotect', 'chmod', 'chown',
            'unlink', 'rename', 'mkdir', 'rmdir',
        ]
        
        for syscall in important_syscalls:
            count = syscall_counts.get(syscall, 0)
            features.numeric_features[f'{self.SYSCALL_PREFIX}{syscall}'] = count
        
        # Syscall category aggregates
        file_read_syscalls = sum(syscall_counts.get(s, 0) for s in 
                                  ['read', 'pread64', 'readv', 'preadv'])
        file_write_syscalls = sum(syscall_counts.get(s, 0) for s in 
                                   ['write', 'pwrite64', 'writev', 'pwritev'])
        file_open_syscalls = sum(syscall_counts.get(s, 0) for s in 
                                  ['open', 'openat', 'creat'])
        process_syscalls = sum(syscall_counts.get(s, 0) for s in 
                               ['execve', 'fork', 'vfork', 'clone', 'clone3'])
        network_syscalls = sum(syscall_counts.get(s, 0) for s in 
                               ['socket', 'connect', 'bind', 'listen', 'accept'])
        
        features.numeric_features[f'{self.PATTERN_PREFIX}file_read_syscalls'] = file_read_syscalls
        features.numeric_features[f'{self.PATTERN_PREFIX}file_write_syscalls'] = file_write_syscalls
        features.numeric_features[f'{self.PATTERN_PREFIX}file_open_syscalls'] = file_open_syscalls
        features.numeric_features[f'{self.PATTERN_PREFIX}process_syscalls'] = process_syscalls
        features.numeric_features[f'{self.PATTERN_PREFIX}network_syscalls'] = network_syscalls
        
        # Read/write ratio from strace
        if file_read_syscalls + file_write_syscalls > 0:
            features.numeric_features[f'{self.PATTERN_PREFIX}write_ratio'] = \
                file_write_syscalls / (file_read_syscalls + file_write_syscalls)
        else:
            features.numeric_features[f'{self.PATTERN_PREFIX}write_ratio'] = 0.0
        
        # Suspicious patterns count (detected during strace parsing)
        suspicious_patterns = patterns.get('suspicious_patterns', [])
        features.numeric_features[f'{self.PATTERN_PREFIX}suspicious_count'] = len(suspicious_patterns)
        
        # Count suspicious pattern types
        suspicious_types = Counter(p.get('type', 'unknown') for p in suspicious_patterns)
        features.numeric_features[f'{self.PATTERN_PREFIX}sensitive_path_access'] = \
            suspicious_types.get('sensitive_path_access', 0)
        features.numeric_features[f'{self.PATTERN_PREFIX}suspicious_execution'] = \
            suspicious_types.get('suspicious_execution', 0)
        
        # Paths analysis from strace
        all_paths = patterns.get('all_paths_accessed', [])
        features.numeric_features[f'{self.PATTERN_PREFIX}unique_paths'] = len(all_paths)
        
        # Analyze paths for sensitive access
        sensitive_path_indicators = [
            '/etc/passwd', '/etc/shadow', '/.ssh/', '/id_rsa', '/id_dsa',
            '/authorized_keys', '/known_hosts', '/etc/crontab', '/cron.d/',
            '/.bashrc', '/.bash_profile', '/.profile', '/.zshrc',
            '/.aws/', '/.config/', '/proc/self/', '/etc/sudoers',
        ]
        
        sensitive_count = 0
        for path in all_paths:
            path_lower = path.lower() if isinstance(path, str) else ''
            for indicator in sensitive_path_indicators:
                if indicator.lower() in path_lower:
                    sensitive_count += 1
                    break
        
        features.numeric_features[f'{self.PATTERN_PREFIX}sensitive_paths_strace'] = sensitive_count
        
        # Installation metadata features
        install_meta = patterns.get('installation', {})
        if install_meta:
            features.numeric_features[f'{self.PATTERN_PREFIX}packages_installed'] = \
                install_meta.get('total_packages', 0)
            features.numeric_features[f'{self.PATTERN_PREFIX}dependencies_count'] = \
                len(install_meta.get('dependencies', []))
            features.numeric_features[f'{self.PATTERN_PREFIX}from_pypi'] = \
                1 if install_meta.get('from_pypi', False) else 0
        else:
            features.numeric_features[f'{self.PATTERN_PREFIX}packages_installed'] = 0
            features.numeric_features[f'{self.PATTERN_PREFIX}dependencies_count'] = 0
            features.numeric_features[f'{self.PATTERN_PREFIX}from_pypi'] = 0
        
        # Error rate from strace
        strace_data = patterns.get('strace', [])
        total_errors = sum(s.get('return_errors', 0) for s in strace_data)
        features.numeric_features[f'{self.PATTERN_PREFIX}syscall_errors'] = total_errors
    
    def _extract_aggregate_features(
        self, 
        parsed_trace: Dict, 
        features: FeatureSet
    ) -> None:
        """Extract aggregate/summary features."""
        
        total_events = parsed_trace.get('total_events', 0)
        features.numeric_features['total_events'] = total_events
        
        # Event density (events per trace)
        file_ops = len(parsed_trace.get('file_operations', []))
        net_ops = len(parsed_trace.get('network_operations', []))
        
        if total_events > 0:
            features.numeric_features['file_op_ratio'] = file_ops / total_events
            features.numeric_features['net_op_ratio'] = net_ops / total_events
        else:
            features.numeric_features['file_op_ratio'] = 0.0
            features.numeric_features['net_op_ratio'] = 0.0
        
        # Combined risk score (heuristic)
        risk_factors = [
            features.numeric_features.get(f'{self.FILE_PREFIX}sensitive_access_count', 0) * 2,
            features.numeric_features.get(f'{self.NET_PREFIX}suspicious_port_count', 0) * 3,
            features.numeric_features.get(f'{self.PATTERN_PREFIX}exfil_indicators', 0) * 2,
            features.numeric_features.get(f'{self.PATTERN_PREFIX}obfusc_indicators', 0) * 2,
            features.numeric_features.get(f'{self.FILE_PREFIX}hidden_files', 0),
        ]
        features.numeric_features['heuristic_risk_score'] = sum(risk_factors)
    
    def _build_sequences(
        self, 
        file_ops: List[Dict], 
        net_ops: List[Dict], 
        features: FeatureSet
    ) -> None:
        """Build operation sequences for sequence models (LSTM)."""
        
        # File operation sequence
        for op in file_ops[:500]:  # Limit sequence length
            op_type = op.get('operation', 'unknown')
            filepath = op.get('filepath', '')
            
            # Encode operation with path category
            path_cat = self._categorize_path(filepath)
            features.syscall_sequence.append(f"{op_type}_{path_cat}")
        
        # Add network operations to sequence
        for op in net_ops[:100]:
            op_type = op.get('operation', 'unknown')
            port = op.get('dst_port', 0)
            port_cat = 'suspicious' if port in SUSPICIOUS_NETWORK['ports'] else 'normal'
            features.syscall_sequence.append(f"net_{op_type}_{port_cat}")
    
    def _categorize_path(self, filepath: str) -> str:
        """Categorize a file path for sequence encoding."""
        if not filepath:
            return 'unknown'
        
        filepath_lower = filepath.lower()
        
        if '/etc/' in filepath_lower:
            return 'etc'
        elif '/.ssh' in filepath_lower or 'id_rsa' in filepath_lower:
            return 'ssh'
        elif '/proc/' in filepath_lower:
            return 'proc'
        elif '/tmp/' in filepath_lower:
            return 'tmp'
        elif '/home/' in filepath_lower or '/root/' in filepath_lower:
            return 'home'
        elif '/usr/' in filepath_lower:
            return 'usr'
        elif '/var/' in filepath_lower:
            return 'var'
        else:
            return 'other'
    
    def get_feature_names(self) -> List[str]:
        """Get list of all numeric feature names."""
        # Return a comprehensive list of all possible features
        feature_names = [
            # File features
            f'{self.FILE_PREFIX}total_ops',
            f'{self.FILE_PREFIX}read_count',
            f'{self.FILE_PREFIX}write_count', 
            f'{self.FILE_PREFIX}open_count',
            f'{self.FILE_PREFIX}write_ratio',
            f'{self.FILE_PREFIX}unique_files',
            f'{self.FILE_PREFIX}total_bytes',
            f'{self.FILE_PREFIX}sensitive_access_count',
            f'{self.FILE_PREFIX}sensitive_ssh_keys',
            f'{self.FILE_PREFIX}sensitive_credentials',
            f'{self.FILE_PREFIX}sensitive_persistence',
            f'{self.FILE_PREFIX}sensitive_shell_config',
            f'{self.FILE_PREFIX}sensitive_cloud_creds',
            f'{self.FILE_PREFIX}sensitive_proc',
            f'{self.FILE_PREFIX}script_files',
            f'{self.FILE_PREFIX}binary_files',
            f'{self.FILE_PREFIX}max_path_depth',
            f'{self.FILE_PREFIX}avg_path_depth',
            f'{self.FILE_PREFIX}hidden_files',
            f'{self.FILE_PREFIX}temp_access',
            
            # Network features
            f'{self.NET_PREFIX}total_ops',
            f'{self.NET_PREFIX}connect_count',
            f'{self.NET_PREFIX}accept_count',
            f'{self.NET_PREFIX}unique_ips',
            f'{self.NET_PREFIX}unique_ports',
            f'{self.NET_PREFIX}suspicious_port_count',
            f'{self.NET_PREFIX}localhost_connections',
            f'{self.NET_PREFIX}external_connections',
            f'{self.NET_PREFIX}high_port_count',
            f'{self.NET_PREFIX}common_port_count',
            
            # Process features
            f'{self.PROC_PREFIX}total_processes',
            f'{self.PROC_PREFIX}unique_names',
            f'{self.PROC_PREFIX}root_processes',
            f'{self.PROC_PREFIX}suspicious_names',
            
            # Pattern/strace features
            f'{self.PATTERN_PREFIX}total_syscalls',
            f'{self.PATTERN_PREFIX}file_read_syscalls',
            f'{self.PATTERN_PREFIX}file_write_syscalls',
            f'{self.PATTERN_PREFIX}file_open_syscalls',
            f'{self.PATTERN_PREFIX}process_syscalls',
            f'{self.PATTERN_PREFIX}network_syscalls',
            f'{self.PATTERN_PREFIX}write_ratio',
            f'{self.PATTERN_PREFIX}suspicious_count',
            f'{self.PATTERN_PREFIX}sensitive_path_access',
            f'{self.PATTERN_PREFIX}suspicious_execution',
            f'{self.PATTERN_PREFIX}unique_paths',
            f'{self.PATTERN_PREFIX}sensitive_paths_strace',
            f'{self.PATTERN_PREFIX}packages_installed',
            f'{self.PATTERN_PREFIX}dependencies_count',
            f'{self.PATTERN_PREFIX}from_pypi',
            f'{self.PATTERN_PREFIX}syscall_errors',
            
            # Aggregate features
            'total_events',
            'file_op_ratio',
            'net_op_ratio',
            'heuristic_risk_score',
        ]
        
        # Add individual syscall features
        important_syscalls = [
            'openat', 'open', 'read', 'write', 'close',
            'stat', 'fstat', 'lstat', 'newfstatat',
            'execve', 'fork', 'clone', 'vfork',
            'socket', 'connect', 'bind', 'listen',
            'mmap', 'mprotect', 'chmod', 'chown',
            'unlink', 'rename', 'mkdir', 'rmdir',
        ]
        for syscall in important_syscalls:
            feature_names.append(f'{self.SYSCALL_PREFIX}{syscall}')
        
        return feature_names


def extract_features_from_traces(
    traces: List[Dict],
    config: Optional[Dict] = None
) -> Tuple[np.ndarray, np.ndarray, List[str], List[FeatureSet]]:
    """
    Extract features from a list of parsed traces.
    
    Args:
        traces: List of parsed trace dictionaries
        config: Optional configuration
        
    Returns:
        X: Feature matrix (n_samples, n_features)
        y: Label vector (n_samples,)
        feature_names: List of feature names
        feature_sets: List of FeatureSet objects
    """
    extractor = FeatureExtractor(config)
    feature_names = extractor.get_feature_names()
    
    feature_sets = []
    X_list = []
    y_list = []
    
    for trace in traces:
        try:
            fs = extractor.extract_features(trace)
            feature_sets.append(fs)
            
            # Build feature vector
            feature_vector = [
                fs.numeric_features.get(name, 0.0) 
                for name in feature_names
            ]
            X_list.append(feature_vector)
            y_list.append(fs.label)
            
        except Exception as e:
            logger.error(f"Error extracting features for {trace.get('package_name')}: {e}")
            continue
    
    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)
    
    return X, y, feature_names, feature_sets
