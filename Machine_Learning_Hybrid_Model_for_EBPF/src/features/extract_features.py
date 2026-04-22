"""
Feature Extraction Script

This script:
1. Loads parsed trace data
2. Extracts features using FeatureExtractor
3. Saves feature matrices for model training
"""

import os
import sys
import argparse
import pickle
import numpy as np
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.features.feature_extractor import FeatureExtractor, extract_features_from_traces
from src.utils.helpers import (
    setup_logging, 
    load_config, 
    load_json,
    save_json,
    ensure_dir,
    Timer
)


def main():
    parser = argparse.ArgumentParser(description='Extract features from parsed traces')
    parser.add_argument('--config', type=str, default='configs/config.yaml',
                        help='Path to config file')
    args = parser.parse_args()
    
    # Setup
    logger = setup_logging(name='extract_features')
    config = load_config(args.config)
    
    processed_dir = config['data']['processed_dir']
    splits_dir = config['data']['splits_dir']
    
    logger.info("="*60)
    logger.info("Feature Extraction")
    logger.info("="*60)
    
    # Process each split
    for split_name in ['train', 'val', 'test']:
        split_file = os.path.join(splits_dir, f'{split_name}.json')
        
        if not os.path.exists(split_file):
            logger.warning(f"Split file not found: {split_file}")
            continue
        
        logger.info(f"Processing {split_name} split...")
        
        with Timer(f"Loading {split_name} data"):
            traces = load_json(split_file)
        
        logger.info(f"Loaded {len(traces)} traces")
        
        with Timer(f"Extracting features for {split_name}"):
            X, y, feature_names, feature_sets = extract_features_from_traces(
                traces=traces,
                config=config.get('features', {})
            )
        
        logger.info(f"Extracted features: X shape = {X.shape}, y shape = {y.shape}")
        logger.info(f"Class distribution - Benign: {sum(y==0)}, Malicious: {sum(y==1)}")
        
        # Save features
        output_dir = os.path.join(processed_dir, 'features')
        ensure_dir(output_dir)
        
        np.save(os.path.join(output_dir, f'X_{split_name}.npy'), X)
        np.save(os.path.join(output_dir, f'y_{split_name}.npy'), y)
        
        # Save feature names (only once)
        if split_name == 'train':
            save_json(feature_names, os.path.join(output_dir, 'feature_names.json'))
        
        # Save sequences for LSTM
        sequences = [fs.syscall_sequence for fs in feature_sets]
        save_json({
            'sequences': sequences,
            'labels': y.tolist(),
            'package_names': [fs.package_name for fs in feature_sets]
        }, os.path.join(output_dir, f'sequences_{split_name}.json'))
        
        logger.info(f"Saved features to {output_dir}")
    
    logger.info("="*60)
    logger.info("Feature extraction complete!")
    logger.info("="*60)


if __name__ == '__main__':
    main()
