#!/usr/bin/env python
"""
Quick Start Script for eBPF Malware Detection Project

This script runs the complete pipeline:
1. Verify dataset location
2. Parse traces (convert raw text files to structured data)
3. Extract features (create numeric features for ML models)
4. Train models (XGBoost + BiLSTM)
5. Evaluate (compare and ensemble models)

Usage:
    python run_pipeline.py --data-dir data/raw
    
Your data should be organized as:
    data/raw/
        benign/
            QUT-DV25_Benign_Raw_Data_Samples/
                QUT-DV25_Filetop_Traces/
                QUT-DV25_Opensnoop_Traces/
                ...
        malicious/
            QUT-DV25_Malicious_Raw_Data_Samples/
                ...
"""

import os
import sys
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(
        description='Run the complete eBPF malware detection pipeline'
    )
    parser.add_argument(
        '--data-dir', 
        type=str, 
        default='data/raw',
        help='Path to raw data directory containing benign/ and malicious/ folders'
    )
    parser.add_argument(
        '--skip-training',
        action='store_true',
        help='Skip model training (only parse and extract features)'
    )
    args = parser.parse_args()
    
    project_root = Path(__file__).parent
    data_dir = Path(args.data_dir)
    
    # Make path absolute if relative
    if not data_dir.is_absolute():
        data_dir = project_root / data_dir
    
    print("="*60)
    print("eBPF Malware Detection Pipeline")
    print("="*60)
    
    # Step 1: Verify data exists
    print("\n[Step 1/5] Verifying data directory...")
    
    # Check for your actual directory structure
    benign_dir = data_dir / 'benign' / 'QUT-DV25_Benign_Raw_Data_Samples'
    malicious_dir = data_dir / 'malicious' / 'QUT-DV25_Malicious_Raw_Data_Samples'
    
    if not benign_dir.exists():
        print(f"ERROR: Benign data not found at {benign_dir}")
        print("\nExpected structure:")
        print("  data/raw/")
        print("    benign/")
        print("      QUT-DV25_Benign_Raw_Data_Samples/")
        print("        QUT-DV25_Filetop_Traces/")
        print("        QUT-DV25_Opensnoop_Traces/")
        print("        ...")
        print("    malicious/")
        print("      QUT-DV25_Malicious_Raw_Data_Samples/")
        print("        ...")
        sys.exit(1)
    
    if not malicious_dir.exists():
        print(f"WARNING: Malicious data not found at {malicious_dir}")
        print("Proceeding with benign data only...")
    
    print(f"✓ Found benign data at: {benign_dir}")
    if malicious_dir.exists():
        print(f"✓ Found malicious data at: {malicious_dir}")
    
    # Step 2: Parse traces
    print("\n[Step 2/5] Parsing trace files...")
    print("  This converts raw text files into structured JSON data...")
    ret = os.system(f'{sys.executable} src/preprocessing/parse_traces.py --data-dir "{data_dir}"')
    if ret != 0:
        print("ERROR: Parsing failed!")
        sys.exit(1)
    print("  ✓ Parsing complete!")
    
    # Step 3: Extract features
    print("\n[Step 3/5] Extracting features...")
    print("  This creates numeric features that ML models can understand...")
    ret = os.system(f'{sys.executable} src/features/extract_features.py')
    if ret != 0:
        print("ERROR: Feature extraction failed!")
        sys.exit(1)
    print("  ✓ Feature extraction complete!")
    
    if not args.skip_training:
        # Step 4: Train models
        print("\n[Step 4/5] Training models...")
        
        print("\n  Training XGBoost (fast, interpretable model)...")
        ret = os.system(f'{sys.executable} src/models/train_xgboost.py')
        if ret != 0:
            print("  WARNING: XGBoost training had issues")
        
        print("\n  Training BiLSTM (deep learning model for sequences)...")
        ret = os.system(f'{sys.executable} src/models/train_lstm.py --epochs 30')
        if ret != 0:
            print("  WARNING: LSTM training had issues")
        
        # Step 5: Evaluate
        print("\n[Step 5/5] Evaluating models...")
        os.system(f'{sys.executable} src/models/evaluate.py')
    else:
        print("\n[Step 4-5/5] Skipping training (--skip-training)")
    
    print("\n" + "="*60)
    print("Pipeline complete!")
    print("="*60)
    print("\nResults:")
    print("  - Parsed data: data/processed/")
    print("  - Features: data/processed/features/")
    print("  - Models: trained_models/")
    print("  - Evaluation: trained_models/evaluation/")
    print("\nTo make predictions on new packages:")
    print(f"  {sys.executable} src/models/inference.py --package-dir /path/to/package/traces")


if __name__ == '__main__':
    main()
