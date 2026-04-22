"""
Main preprocessing script for parsing all trace files.

This script:
1. Reads all trace files from raw data directories
2. Parses them using appropriate parsers
3. Saves parsed data to intermediate JSON files
4. Creates train/val/test splits
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict
import random

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.preprocessing.trace_parsers import UnifiedTraceParser, ParsedTrace
from src.utils.helpers import (
    setup_logging, 
    load_config, 
    save_json,
    ensure_dir,
    Timer,
    extract_package_name
)


def discover_packages(base_dir: str) -> List[str]:
    """
    Discover all package names from trace files in a directory.
    
    QUT-DV25 naming conventions:
    - Filetop: {package}_filetop_trace.txt
    - Opensnoop: {package}_opensnoop_trace.txt  
    - TCP: {package}_tcptraces.txt
    - Installation: {package}_install_log.txt
    - PIDs: traced_pids_{package}.txt
    - Pattern: {package}/ (directory)
    """
    packages = set()
    
    # Check Filetop traces directory: {package}_filetop_trace.txt
    filetop_dir = os.path.join(base_dir, 'QUT-DV25_Filetop_Traces')
    if os.path.exists(filetop_dir):
        for filename in os.listdir(filetop_dir):
            if filename.endswith('_filetop_trace.txt'):
                package_name = filename.replace('_filetop_trace.txt', '')
                packages.add(package_name)
    
    # Check Opensnoop traces: {package}_opensnoop_trace.txt
    opensnoop_dir = os.path.join(base_dir, 'QUT-DV25_Opensnoop_Traces')
    if os.path.exists(opensnoop_dir):
        for filename in os.listdir(opensnoop_dir):
            if filename.endswith('_opensnoop_trace.txt'):
                package_name = filename.replace('_opensnoop_trace.txt', '')
                packages.add(package_name)
    
    # Check TCP traces: {package}_tcptraces.txt
    tcp_dir = os.path.join(base_dir, 'QUT-DV25_TCP_Traces')
    if os.path.exists(tcp_dir):
        for filename in os.listdir(tcp_dir):
            if filename.endswith('_tcptraces.txt'):
                package_name = filename.replace('_tcptraces.txt', '')
                packages.add(package_name)
    
    # Check Installation traces: {package}_install_log.txt
    install_dir = os.path.join(base_dir, 'QUT-DV25_Installation_Traces')
    if os.path.exists(install_dir):
        for filename in os.listdir(install_dir):
            if filename.endswith('_install_log.txt'):
                package_name = filename.replace('_install_log.txt', '')
                packages.add(package_name)
    
    # Check PIDs: traced_pids_{package}.txt
    pid_dir = os.path.join(base_dir, 'QUT-DV25_PIDs')
    if os.path.exists(pid_dir):
        for filename in os.listdir(pid_dir):
            if filename.startswith('traced_pids_') and filename.endswith('.txt'):
                package_name = filename.replace('traced_pids_', '').replace('.txt', '')
                packages.add(package_name)
    
    # Check Pattern traces (directories): {package}/
    pattern_dir = os.path.join(base_dir, 'QUT-DV25_Pattern_Traces')
    if os.path.exists(pattern_dir):
        for item in os.listdir(pattern_dir):
            item_path = os.path.join(pattern_dir, item)
            if os.path.isdir(item_path):
                packages.add(item)
    
    return sorted(list(packages))


def parse_all_traces(
    raw_dir: str,
    output_dir: str,
    logger
) -> Tuple[List[Dict], List[Dict]]:
    """
    Parse all trace files for benign and malicious samples.
    
    Handles directory structure:
        raw_dir/
            benign/
                QUT-DV25_Benign_Raw_Data_Samples/
            malicious/
                QUT-DV25_Malicious_Raw_Data_Samples/
    
    Args:
        raw_dir: Directory containing raw trace data
        output_dir: Directory to save parsed data
        logger: Logger instance
        
    Returns:
        Tuple of (benign_traces, malicious_traces)
    """
    parser = UnifiedTraceParser()
    
    # Support both structures:
    # 1. raw_dir/benign/QUT-DV25_Benign_Raw_Data_Samples/
    # 2. raw_dir/QUT-DV25_Benign_Raw_Data_Samples/
    
    benign_dir = os.path.join(raw_dir, 'benign', 'QUT-DV25_Benign_Raw_Data_Samples')
    if not os.path.exists(benign_dir):
        benign_dir = os.path.join(raw_dir, 'QUT-DV25_Benign_Raw_Data_Samples')
    
    malicious_dir = os.path.join(raw_dir, 'malicious', 'QUT-DV25_Malicious_Raw_Data_Samples')
    if not os.path.exists(malicious_dir):
        malicious_dir = os.path.join(raw_dir, 'QUT-DV25_Malicious_Raw_Data_Samples')
    
    benign_traces = []
    malicious_traces = []
    
    # Parse benign samples
    if os.path.exists(benign_dir):
        logger.info(f"Parsing benign samples from {benign_dir}")
        benign_packages = discover_packages(benign_dir)
        logger.info(f"Found {len(benign_packages)} benign packages")
        
        for i, package_name in enumerate(benign_packages):
            try:
                trace = parser.parse_package_traces(
                    package_name=package_name,
                    base_dir=benign_dir,
                    label=0  # Benign
                )
                if trace.total_events > 0:
                    benign_traces.append(trace.to_dict())
                    if (i + 1) % 50 == 0:
                        logger.info(f"  Parsed {i + 1}/{len(benign_packages)} benign packages...")
            except Exception as e:
                logger.error(f"Error parsing benign package {package_name}: {e}")
        
        logger.info(f"  ✓ Completed parsing {len(benign_traces)} benign packages")
    else:
        logger.warning(f"Benign directory not found: {benign_dir}")
    
    # Parse malicious samples
    if os.path.exists(malicious_dir):
        logger.info(f"Parsing malicious samples from {malicious_dir}")
        malicious_packages = discover_packages(malicious_dir)
        logger.info(f"Found {len(malicious_packages)} malicious packages")
        
        for i, package_name in enumerate(malicious_packages):
            try:
                trace = parser.parse_package_traces(
                    package_name=package_name,
                    base_dir=malicious_dir,
                    label=1  # Malicious
                )
                if trace.total_events > 0:
                    malicious_traces.append(trace.to_dict())
                    if (i + 1) % 50 == 0:
                        logger.info(f"  Parsed {i + 1}/{len(malicious_packages)} malicious packages...")
            except Exception as e:
                logger.error(f"Error parsing malicious package {package_name}: {e}")
        
        logger.info(f"  ✓ Completed parsing {len(malicious_traces)} malicious packages")
    else:
        logger.warning(f"Malicious directory not found: {malicious_dir}")
    
    return benign_traces, malicious_traces


def create_splits(
    benign_traces: List[Dict],
    malicious_traces: List[Dict],
    splits_dir: str,
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_seed: int = 42,
    logger = None
) -> Dict[str, List[Dict]]:
    """
    Create train/val/test splits while maintaining class balance.
    """
    random.seed(random_seed)
    
    # Shuffle both lists
    random.shuffle(benign_traces)
    random.shuffle(malicious_traces)
    
    def split_list(data: List, train_r: float, val_r: float):
        n = len(data)
        train_end = int(n * train_r)
        val_end = int(n * (train_r + val_r))
        return data[:train_end], data[train_end:val_end], data[val_end:]
    
    # Split benign
    ben_train, ben_val, ben_test = split_list(benign_traces, train_ratio, val_ratio)
    
    # Split malicious
    mal_train, mal_val, mal_test = split_list(malicious_traces, train_ratio, val_ratio)
    
    # Combine
    train_data = ben_train + mal_train
    val_data = ben_val + mal_val
    test_data = ben_test + mal_test
    
    # Shuffle combined sets
    random.shuffle(train_data)
    random.shuffle(val_data)
    random.shuffle(test_data)
    
    splits = {
        'train': train_data,
        'val': val_data,
        'test': test_data
    }
    
    # Save splits
    ensure_dir(splits_dir)
    for split_name, split_data in splits.items():
        filepath = os.path.join(splits_dir, f'{split_name}.json')
        save_json(split_data, filepath)
        if logger:
            benign_count = sum(1 for d in split_data if d['label'] == 0)
            mal_count = sum(1 for d in split_data if d['label'] == 1)
            logger.info(f"{split_name}: {len(split_data)} samples (Benign: {benign_count}, Malicious: {mal_count})")
    
    return splits


def main():
    parser = argparse.ArgumentParser(description='Parse eBPF trace files')
    parser.add_argument('--config', type=str, default='configs/config.yaml',
                        help='Path to config file')
    parser.add_argument('--data-dir', type=str, default=None,
                        help='Override raw data directory (e.g., data/raw)')
    args = parser.parse_args()
    
    # Setup
    logger = setup_logging(name='parse_traces')
    config = load_config(args.config)
    
    # Use command line arg if provided, otherwise use config
    raw_dir = args.data_dir if args.data_dir else config['data']['raw_dir']
    processed_dir = config['data']['processed_dir']
    splits_dir = config['data']['splits_dir']
    
    logger.info("="*60)
    logger.info("eBPF Trace Parser")
    logger.info("="*60)
    logger.info(f"Raw data directory: {raw_dir}")
    logger.info(f"Processed data directory: {processed_dir}")
    
    # Check if raw data exists
    if not os.path.exists(raw_dir):
        logger.error(f"Raw data directory does not exist: {raw_dir}")
        logger.info("Please copy or link your QUT-DV25 dataset to the raw data directory:")
        logger.info(f"  - {raw_dir}/QUT-DV25_Benign_Raw_Data_Samples/")
        logger.info(f"  - {raw_dir}/QUT-DV25_Malicious_Raw_Data_Samples/")
        return
    
    # Parse all traces
    with Timer("Parsing all trace files"):
        benign_traces, malicious_traces = parse_all_traces(
            raw_dir=raw_dir,
            output_dir=processed_dir,
            logger=logger
        )
    
    logger.info(f"Total benign traces: {len(benign_traces)}")
    logger.info(f"Total malicious traces: {len(malicious_traces)}")
    
    # Save all parsed data
    ensure_dir(processed_dir)
    save_json(benign_traces, os.path.join(processed_dir, 'benign_parsed.json'))
    save_json(malicious_traces, os.path.join(processed_dir, 'malicious_parsed.json'))
    
    # Create splits
    if len(benign_traces) > 0 or len(malicious_traces) > 0:
        logger.info("Creating train/val/test splits...")
        splits = create_splits(
            benign_traces=benign_traces,
            malicious_traces=malicious_traces,
            splits_dir=splits_dir,
            train_ratio=config['splits']['train'],
            val_ratio=config['splits']['val'],
            test_ratio=config['splits']['test'],
            random_seed=config['splits']['random_seed'],
            logger=logger
        )
    else:
        logger.warning("No traces parsed. Check your data directory.")
    
    logger.info("="*60)
    logger.info("Parsing complete!")
    logger.info("="*60)


if __name__ == '__main__':
    main()
