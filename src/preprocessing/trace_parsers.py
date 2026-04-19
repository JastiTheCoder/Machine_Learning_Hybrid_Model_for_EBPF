"""
Trace File Parsers for eBPF/BCC Data (QUT-DV25 Dataset)

This module contains parsers for different types of eBPF trace files:
- Filetop: File I/O operations (bcc/filetop)
- Opensnoop: File open syscalls (bcc/opensnoop)
- TCP: Network connections (bcc/tcpstates)
- Installation: pip install logs
- Pattern: strace syscall traces
- PIDs: Process IDs

Data Format (QUT-DV25):
- Opensnoop: PID COMM FD ERR PATH
- TCP: SKADDR C-PID C-COMM LADDR LPORT RADDR RPORT OLDSTATE -> NEWSTATE MS
- Pattern: strace output with timestamp, syscall(args) = return_value
- PIDs: Single PID per line

Each parser returns a standardized format for downstream processing.
"""

import os
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import defaultdict, Counter
import logging

logger = logging.getLogger(__name__)


@dataclass
class FileOperation:
    """Represents a single file operation."""
    timestamp: Optional[float] = None
    pid: Optional[int] = None
    process_name: str = ""
    operation: str = ""  # read, write, open, etc.
    filepath: str = ""
    bytes_count: int = 0
    flags: str = ""
    return_value: Optional[int] = None


@dataclass
class NetworkOperation:
    """Represents a network operation."""
    timestamp: Optional[float] = None
    pid: Optional[int] = None
    process_name: str = ""
    operation: str = ""  # connect, bind, accept, etc.
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""


@dataclass
class ProcessInfo:
    """Represents process information."""
    pid: int = 0
    ppid: int = 0
    process_name: str = ""
    command_line: str = ""
    user: str = ""
    start_time: Optional[float] = None


@dataclass
class ParsedTrace:
    """Container for all parsed trace data for a single package."""
    package_name: str = ""
    label: int = 0  # 0 = benign, 1 = malicious
    
    # Raw parsed events
    file_operations: List[FileOperation] = field(default_factory=list)
    network_operations: List[NetworkOperation] = field(default_factory=list)
    process_info: List[ProcessInfo] = field(default_factory=list)
    
    # Installation events
    installation_commands: List[str] = field(default_factory=list)
    
    # Pattern data
    patterns: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    trace_duration: float = 0.0
    total_events: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'package_name': self.package_name,
            'label': self.label,
            'file_operations': [asdict(op) for op in self.file_operations],
            'network_operations': [asdict(op) for op in self.network_operations],
            'process_info': [asdict(p) for p in self.process_info],
            'installation_commands': self.installation_commands,
            'patterns': self.patterns,
            'trace_duration': self.trace_duration,
            'total_events': self.total_events,
        }


class FiletopParser:
    """
    Parser for filetop trace files.
    
    Filetop shows file I/O by process, including reads and writes.
    Expected format varies, but typically:
    - Header with timestamp/interval info
    - PID, COMM, READS, WRITES, R_KB, W_KB, T(ype), FILE
    """
    
    def __init__(self):
        # Common patterns for filetop output
        # Pattern 1: Standard bcc filetop
        self.header_pattern = re.compile(
            r'(?:TID|PID)\s+COMM\s+(?:READS|READ)\s+(?:WRITES|WRITE)\s+R_KB\s+W_KB\s+T\s+FILE',
            re.IGNORECASE
        )
        # Data row pattern
        self.data_pattern = re.compile(
            r'(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+(\w)\s+(.+)',
            re.IGNORECASE
        )
    
    def parse(self, filepath: str) -> List[FileOperation]:
        """Parse a filetop trace file."""
        operations = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Error reading {filepath}: {e}")
            return operations
        
        for line in lines:
            line = line.strip()
            if not line or self.header_pattern.match(line):
                continue
            
            match = self.data_pattern.match(line)
            if match:
                pid, comm, reads, writes, r_kb, w_kb, ftype, filename = match.groups()
                
                # Create read operation if reads > 0
                if int(reads) > 0:
                    operations.append(FileOperation(
                        pid=int(pid),
                        process_name=comm,
                        operation='read',
                        filepath=filename,
                        bytes_count=int(float(r_kb) * 1024),
                    ))
                
                # Create write operation if writes > 0
                if int(writes) > 0:
                    operations.append(FileOperation(
                        pid=int(pid),
                        process_name=comm,
                        operation='write',
                        filepath=filename,
                        bytes_count=int(float(w_kb) * 1024),
                    ))
        
        logger.info(f"Parsed {len(operations)} file operations from {filepath}")
        return operations


class OpensnoopParser:
    """
    Parser for opensnoop trace files (bcc/opensnoop).
    
    QUT-DV25 Format:
    PID    COMM               FD ERR PATH
    86747  pip                 3   0 /path/to/file
    86747  pip                -1   2 /path/that/failed
    
    FD: File descriptor (positive = success, negative = error indicator)
    ERR: Error code (0 = success, 2 = ENOENT, etc.)
    """
    
    def __init__(self):
        # Pattern for opensnoop data lines
        # Format: PID COMM FD ERR PATH
        self.data_pattern = re.compile(
            r'^(\d+)\s+(\S+)\s+(-?\d+)\s+(\d+)\s+(.+)$'
        )
        # Skip header lines
        self.header_keywords = ['PID', 'COMM', 'FD', 'ERR', 'PATH']
    
    def parse(self, filepath: str) -> List[FileOperation]:
        """Parse an opensnoop trace file."""
        operations = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Error reading {filepath}: {e}")
            return operations
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Skip header lines
            if any(kw in line for kw in self.header_keywords):
                # But only if it looks like a header (not a path containing these words)
                if line.startswith('PID') or 'COMM' in line.split()[:3]:
                    continue
            
            match = self.data_pattern.match(line)
            if match:
                pid, comm, fd, err, path = match.groups()
                fd_int = int(fd)
                err_int = int(err)
                
                operations.append(FileOperation(
                    pid=int(pid),
                    process_name=comm,
                    operation='open',
                    filepath=path.strip(),
                    return_value=fd_int,
                    flags=f"err={err_int}" if err_int != 0 else "success",
                ))
        
        logger.info(f"Parsed {len(operations)} open operations from {filepath}")
        return operations


class TCPParser:
    """
    Parser for TCP trace files (bcc/tcpstates).
    
    QUT-DV25 Format (tcpstates):
    SKADDR           C-PID C-COMM     LADDR           LPORT RADDR           RPORT OLDSTATE    -> NEWSTATE    MS
    ffff937438611bc0 86747 pip        192.168.0.105   0     151.101.0.223   443   CLOSE       -> SYN_SENT    0.000
    
    This traces TCP state changes, showing:
    - Which process initiated connections
    - Source/destination IPs and ports
    - Connection lifecycle (SYN_SENT -> ESTABLISHED -> FIN_WAIT, etc.)
    """
    
    def __init__(self):
        # Pattern for tcpstates output
        # SKADDR C-PID C-COMM LADDR LPORT RADDR RPORT OLDSTATE -> NEWSTATE MS
        self.data_pattern = re.compile(
            r'^([0-9a-fA-F]+)\s+'      # SKADDR (hex)
            r'(\d+)\s+'                 # C-PID
            r'(\S+)\s+'                 # C-COMM
            r'([\d.]+)\s+'              # LADDR (local IP)
            r'(\d+)\s+'                 # LPORT
            r'([\d.]+)\s+'              # RADDR (remote IP)
            r'(\d+)\s+'                 # RPORT
            r'(\w+)\s+'                 # OLDSTATE
            r'->\s+'                    # arrow
            r'(\w+)\s+'                 # NEWSTATE
            r'([\d.]+)'                 # MS (milliseconds)
        )
        self.header_keywords = ['SKADDR', 'C-PID', 'LADDR', 'RADDR', 'OLDSTATE', 'NEWSTATE']
    
    def parse(self, filepath: str) -> List[NetworkOperation]:
        """Parse a TCP trace file."""
        operations = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Error reading {filepath}: {e}")
            return operations
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Skip header lines
            if any(kw in line for kw in self.header_keywords[:3]):
                continue
            
            match = self.data_pattern.match(line)
            if match:
                (skaddr, pid, comm, laddr, lport, raddr, rport, 
                 old_state, new_state, ms) = match.groups()
                
                # Determine operation type based on state transition
                operation = self._state_to_operation(old_state, new_state)
                
                operations.append(NetworkOperation(
                    timestamp=float(ms) / 1000.0,  # Convert ms to seconds
                    pid=int(pid),
                    process_name=comm,
                    operation=operation,
                    src_ip=laddr,
                    src_port=int(lport),
                    dst_ip=raddr,
                    dst_port=int(rport),
                    protocol=f"{old_state}->{new_state}",
                ))
        
        logger.info(f"Parsed {len(operations)} network operations from {filepath}")
        return operations
    
    def _state_to_operation(self, old_state: str, new_state: str) -> str:
        """Convert TCP state transition to operation type."""
        if new_state == 'SYN_SENT':
            return 'connect_init'
        elif new_state == 'ESTABLISHED':
            return 'connect_established'
        elif new_state in ('FIN_WAIT1', 'FIN_WAIT2', 'CLOSE_WAIT', 'CLOSING'):
            return 'close_init'
        elif new_state == 'CLOSE':
            return 'close'
        elif new_state == 'LAST_ACK':
            return 'close_ack'
        elif new_state == 'LISTEN':
            return 'listen'
        else:
            return f"state_{new_state.lower()}"


class InstallationParser:
    """
    Parser for installation trace files (pip install logs).
    
    QUT-DV25 Format - pip install output:
    Collecting PackageName
      Downloading package-version.whl (size)
    Installing collected packages: pkg1, pkg2, ...
    Successfully installed pkg1-version pkg2-version
    
    Extracts:
    - Package names and versions being installed
    - Download URLs/sources
    - Dependencies
    """
    
    def __init__(self):
        # Patterns for pip install output
        self.collecting_pattern = re.compile(r'Collecting\s+(\S+)')
        self.downloading_pattern = re.compile(r'Downloading\s+(\S+)')
        self.installing_pattern = re.compile(r'Installing collected packages:\s+(.+)')
        self.success_pattern = re.compile(r'Successfully installed\s+(.+)')
        self.requirement_pattern = re.compile(r'Requirement already satisfied:\s+(\S+)')
        self.dependency_pattern = re.compile(r'\(from\s+(.+?)\)')
    
    def parse(self, filepath: str) -> Tuple[List[str], List[FileOperation], Dict[str, Any]]:
        """
        Parse an installation trace file.
        
        Returns:
            Tuple of (commands, operations, metadata)
            - commands: List of package names being installed
            - operations: FileOperation objects for tracking
            - metadata: Dict with parsed installation details
        """
        commands = []
        operations = []
        metadata = {
            'packages_collected': [],
            'packages_installed': [],
            'download_urls': [],
            'dependencies': [],
            'from_pypi': False,
            'total_packages': 0,
        }
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            logger.error(f"Error reading {filepath}: {e}")
            return commands, operations, metadata
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Collecting packages
            match = self.collecting_pattern.search(line)
            if match:
                pkg = match.group(1)
                commands.append(f"collect:{pkg}")
                metadata['packages_collected'].append(pkg)
            
            # Downloading URLs
            match = self.downloading_pattern.search(line)
            if match:
                url = match.group(1)
                metadata['download_urls'].append(url)
                if 'pypi.org' in url or 'pythonhosted' in url:
                    metadata['from_pypi'] = True
            
            # Successfully installed
            match = self.success_pattern.search(line)
            if match:
                installed = match.group(1).split()
                metadata['packages_installed'].extend(installed)
                for pkg in installed:
                    commands.append(f"install:{pkg}")
            
            # Dependencies
            match = self.dependency_pattern.search(line)
            if match:
                dep = match.group(1)
                metadata['dependencies'].append(dep)
        
        metadata['total_packages'] = len(set(metadata['packages_installed']))
        
        # Create a summary operation
        operations.append(FileOperation(
            operation='pip_install',
            filepath=filepath,
            bytes_count=metadata['total_packages'],
        ))
        
        logger.info(f"Parsed {len(commands)} install commands from {filepath}")
        return commands, operations, metadata


class PIDParser:
    """
    Parser for PID trace files.
    
    QUT-DV25 Format:
    Simple file containing one or more PIDs (one per line):
    86747
    
    These PIDs link all the other traces together for the same package.
    """
    
    def parse(self, filepath: str) -> List[ProcessInfo]:
        """Parse a PID trace file."""
        processes = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Error reading {filepath}: {e}")
            return processes
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Each line should be a PID
            if line.isdigit():
                processes.append(ProcessInfo(
                    pid=int(line),
                    process_name='pip',  # Main process for package installation
                ))
        
        logger.info(f"Parsed {len(processes)} PIDs from {filepath}")
        return processes


class PatternParser:
    """
    Parser for pattern trace files (strace output).
    
    QUT-DV25 Format - strace output:
    15:03:06 newfstatat(AT_FDCWD, "/path/to/file", {st_mode=...}, 0) = 0
    15:03:06 openat(AT_FDCWD, "/path/to/file", O_RDONLY|O_CLOEXEC) = 3
    15:03:06 write(3, "data...", 35238) = 35238
    15:03:06 close(3) = 0
    15:03:06 rename("/old/path", "/new/path") = 0
    
    This is the MOST VALUABLE data for malware detection as it shows:
    - Every syscall made during installation
    - File paths accessed
    - Data written/read
    - Network operations
    - Process creation
    """
    
    def __init__(self):
        # Pattern for strace lines
        # Format: TIMESTAMP SYSCALL(ARGS) = RETURN
        self.strace_pattern = re.compile(
            r'^(\d{2}:\d{2}:\d{2})\s+'   # Timestamp HH:MM:SS
            r'(\w+)\s*'                   # Syscall name
            r'\((.+?)\)\s*'               # Arguments
            r'=\s*(-?\d+|0x[0-9a-fA-F]+|\?)' # Return value
        )
        
        # Patterns for extracting paths from syscall arguments
        self.path_pattern = re.compile(r'"([^"]+)"')
        
        # Syscalls to track
        self.file_syscalls = {
            'openat', 'open', 'creat', 'read', 'write', 'close',
            'stat', 'fstat', 'lstat', 'newfstatat', 'statx',
            'access', 'faccessat', 'rename', 'renameat', 'renameat2',
            'unlink', 'unlinkat', 'mkdir', 'mkdirat', 'rmdir',
            'chmod', 'fchmod', 'chown', 'fchown', 'lchown',
            'link', 'linkat', 'symlink', 'symlinkat', 'readlink',
        }
        
        self.process_syscalls = {
            'execve', 'execveat', 'fork', 'vfork', 'clone', 'clone3',
            'wait4', 'waitid', 'exit', 'exit_group',
        }
        
        self.network_syscalls = {
            'socket', 'connect', 'bind', 'listen', 'accept', 'accept4',
            'send', 'sendto', 'sendmsg', 'recv', 'recvfrom', 'recvmsg',
            'setsockopt', 'getsockopt', 'getpeername', 'getsockname',
        }
        
        self.memory_syscalls = {
            'mmap', 'mmap2', 'munmap', 'mprotect', 'mremap',
            'brk', 'sbrk',
        }
    
    def parse(self, filepath: str) -> Dict[str, Any]:
        """Parse a strace pattern trace file."""
        patterns = {
            'raw_lines': [],
            'syscall_counts': Counter(),
            'syscall_sequence': [],
            'file_operations': [],
            'paths_accessed': set(),
            'paths_written': set(),
            'paths_read': set(),
            'suspicious_patterns': [],
            'timestamps': [],
            'return_errors': 0,
        }
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Error reading {filepath}: {e}")
            return self._finalize_patterns(patterns)
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            patterns['raw_lines'].append(line)
            
            match = self.strace_pattern.match(line)
            if match:
                timestamp, syscall, args, ret_val = match.groups()
                
                patterns['timestamps'].append(timestamp)
                patterns['syscall_counts'][syscall] += 1
                patterns['syscall_sequence'].append(syscall)
                
                # Check for errors
                if ret_val.startswith('-') or ret_val == '?':
                    patterns['return_errors'] += 1
                
                # Extract paths from arguments
                paths = self.path_pattern.findall(args)
                for path in paths:
                    patterns['paths_accessed'].add(path)
                    
                    # Track read vs write
                    if syscall in ('write', 'pwrite64', 'writev'):
                        patterns['paths_written'].add(path)
                    elif syscall in ('read', 'pread64', 'readv'):
                        patterns['paths_read'].add(path)
                
                # Create file operation for relevant syscalls
                if syscall in self.file_syscalls and paths:
                    patterns['file_operations'].append({
                        'timestamp': timestamp,
                        'syscall': syscall,
                        'path': paths[0] if paths else '',
                        'return': ret_val,
                    })
                
                # Check for suspicious patterns
                self._check_suspicious(syscall, args, paths, patterns)
        
        return self._finalize_patterns(patterns)
    
    def _check_suspicious(
        self, 
        syscall: str, 
        args: str, 
        paths: List[str], 
        patterns: Dict
    ):
        """Check for suspicious syscall patterns."""
        suspicious_paths = [
            '/etc/passwd', '/etc/shadow', '/.ssh/', '/id_rsa',
            '/etc/crontab', '/cron.d/', '/etc/sudoers',
            '/.bashrc', '/.bash_profile', '/.profile',
            '/proc/self/', '/.aws/', '/.config/',
        ]
        
        suspicious_syscalls_with_context = [
            ('execve', 'curl'),
            ('execve', 'wget'),
            ('execve', 'nc'),
            ('execve', 'base64'),
            ('execve', 'sh'),
            ('socket', 'SOCK_RAW'),
        ]
        
        # Check paths
        for path in paths:
            path_lower = path.lower()
            for sus_path in suspicious_paths:
                if sus_path.lower() in path_lower:
                    patterns['suspicious_patterns'].append({
                        'type': 'sensitive_path_access',
                        'syscall': syscall,
                        'path': path,
                    })
                    break
        
        # Check syscall + args combinations
        args_lower = args.lower()
        for sus_syscall, sus_arg in suspicious_syscalls_with_context:
            if syscall == sus_syscall and sus_arg.lower() in args_lower:
                patterns['suspicious_patterns'].append({
                    'type': 'suspicious_execution',
                    'syscall': syscall,
                    'detail': sus_arg,
                })
    
    def _finalize_patterns(self, patterns: Dict) -> Dict:
        """Convert sets to lists for JSON serialization."""
        patterns['paths_accessed'] = list(patterns['paths_accessed'])
        patterns['paths_written'] = list(patterns['paths_written'])
        patterns['paths_read'] = list(patterns['paths_read'])
        patterns['syscall_counts'] = dict(patterns['syscall_counts'])
        return patterns


class UnifiedTraceParser:
    """
    Unified parser that combines all trace types for a single package.
    
    Handles QUT-DV25 dataset file naming conventions:
    - Filetop: {package}_filetop_trace.txt
    - Opensnoop: {package}_opensnoop_trace.txt
    - TCP: {package}_tcptraces.txt
    - Installation: {package}_install_log.txt
    - PIDs: traced_pids_{package}.txt
    - Pattern (strace): {package}/strace_output_{pid}.{pid}
    """
    
    def __init__(self):
        self.filetop_parser = FiletopParser()
        self.opensnoop_parser = OpensnoopParser()
        self.tcp_parser = TCPParser()
        self.installation_parser = InstallationParser()
        self.pid_parser = PIDParser()
        self.pattern_parser = PatternParser()
    
    def parse_package_traces(
        self,
        package_name: str,
        base_dir: str,
        label: int = 0
    ) -> ParsedTrace:
        """
        Parse all trace files for a single package.
        
        Args:
            package_name: Name of the package
            base_dir: Base directory containing trace subdirectories
            label: 0 for benign, 1 for malicious
            
        Returns:
            ParsedTrace object with all parsed data
        """
        trace = ParsedTrace(package_name=package_name, label=label)
        
        # Filetop traces: {package}_filetop_trace.txt
        filetop_path = os.path.join(
            base_dir, 'QUT-DV25_Filetop_Traces',
            f'{package_name}_filetop_trace.txt'
        )
        if os.path.exists(filetop_path):
            trace.file_operations.extend(self.filetop_parser.parse(filetop_path))
        
        # Opensnoop traces: {package}_opensnoop_trace.txt
        opensnoop_path = os.path.join(
            base_dir, 'QUT-DV25_Opensnoop_Traces',
            f'{package_name}_opensnoop_trace.txt'
        )
        if os.path.exists(opensnoop_path):
            trace.file_operations.extend(self.opensnoop_parser.parse(opensnoop_path))
        
        # TCP traces: {package}_tcptraces.txt
        tcp_path = os.path.join(
            base_dir, 'QUT-DV25_TCP_Traces',
            f'{package_name}_tcptraces.txt'
        )
        if os.path.exists(tcp_path):
            trace.network_operations.extend(self.tcp_parser.parse(tcp_path))
        
        # Installation traces: {package}_install_log.txt
        install_path = os.path.join(
            base_dir, 'QUT-DV25_Installation_Traces',
            f'{package_name}_install_log.txt'
        )
        if os.path.exists(install_path):
            commands, ops, metadata = self.installation_parser.parse(install_path)
            trace.installation_commands = commands
            trace.file_operations.extend(ops)
            # Store installation metadata in patterns
            trace.patterns['installation'] = metadata
        
        # PID traces: traced_pids_{package}.txt
        pid_path = os.path.join(
            base_dir, 'QUT-DV25_PIDs',
            f'traced_pids_{package_name}.txt'
        )
        if os.path.exists(pid_path):
            trace.process_info = self.pid_parser.parse(pid_path)
        
        # Pattern traces (strace): {package}/strace_output_*.* 
        pattern_dir = os.path.join(
            base_dir, 'QUT-DV25_Pattern_Traces',
            package_name
        )
        if os.path.exists(pattern_dir) and os.path.isdir(pattern_dir):
            # Find all strace files in the package directory
            strace_patterns = self._parse_all_strace_files(pattern_dir)
            trace.patterns['strace'] = strace_patterns
            
            # Merge syscall counts
            if 'syscall_counts' not in trace.patterns:
                trace.patterns['syscall_counts'] = {}
            
            for sp in strace_patterns:
                for syscall, count in sp.get('syscall_counts', {}).items():
                    trace.patterns['syscall_counts'][syscall] = \
                        trace.patterns['syscall_counts'].get(syscall, 0) + count
            
            # Merge suspicious patterns
            trace.patterns['suspicious_patterns'] = []
            for sp in strace_patterns:
                trace.patterns['suspicious_patterns'].extend(
                    sp.get('suspicious_patterns', [])
                )
            
            # Merge paths
            trace.patterns['all_paths_accessed'] = set()
            for sp in strace_patterns:
                trace.patterns['all_paths_accessed'].update(
                    sp.get('paths_accessed', [])
                )
            trace.patterns['all_paths_accessed'] = list(
                trace.patterns['all_paths_accessed']
            )
        
        # Calculate totals
        trace.total_events = (
            len(trace.file_operations) +
            len(trace.network_operations) +
            len(trace.process_info) +
            sum(trace.patterns.get('syscall_counts', {}).values())
        )
        
        return trace
    
    def _parse_all_strace_files(self, pattern_dir: str) -> List[Dict]:
        """Parse all strace files in a directory."""
        strace_patterns = []
        
        for filename in os.listdir(pattern_dir):
            if filename.startswith('strace_output'):
                filepath = os.path.join(pattern_dir, filename)
                if os.path.isfile(filepath):
                    parsed = self.pattern_parser.parse(filepath)
                    parsed['source_file'] = filename
                    strace_patterns.append(parsed)
        
        return strace_patterns


def get_parser_for_trace_type(trace_type: str):
    """Factory function to get appropriate parser."""
    parsers = {
        'filetop': FiletopParser(),
        'opensnoop': OpensnoopParser(),
        'tcp': TCPParser(),
        'installation': InstallationParser(),
        'pids': PIDParser(),
        'pattern': PatternParser(),
    }
    return parsers.get(trace_type.lower())
