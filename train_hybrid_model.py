"""
Hybrid XGBoost + LSTM Ensemble Model for Malware Detection

This script implements a stacking ensemble approach:
1. XGBoost produces prediction probabilities and leaf indices
2. These are combined with original features and fed to LSTM
3. LSTM makes the final classification decision

Why Hybrid Approach?
- XGBoost: Excels at tabular data, captures feature interactions
- LSTM: Can learn sequential patterns and temporal dependencies
- Combined: Reduces individual model biases, leverages complementary strengths
"""

import os
import sys
import json
import numpy as np
from pathlib import Path
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score, roc_curve
)
import logging

# Add project root
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.features.qut_feature_extractor import (
    QUTFeatureExtractor, 
    QUT_FEATURE_NAMES,
    extract_qut_features_from_parsed_data
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class HybridXGBoostLSTM:
    """
    Hybrid ensemble model combining XGBoost and LSTM.
    
    Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    INPUT (36 QUT Features)                  │
    └─────────────────────────────────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
    ┌───────────────────────────┐   ┌───────────────────────────┐
    │        XGBoost            │   │    Original Features      │
    │  (Tree-based learning)    │   │      (Normalized)         │
    └───────────────────────────┘   └───────────────────────────┘
                    │                           │
                    ▼                           │
    ┌───────────────────────────┐               │
    │  XGBoost Outputs:         │               │
    │  - Probability scores     │               │
    │  - Leaf indices (encoded) │               │
    └───────────────────────────┘               │
                    │                           │
                    └─────────────┬─────────────┘
                                  ▼
    ┌─────────────────────────────────────────────────────────────┐
    │              CONCATENATED FEATURE VECTOR                    │
    │     [Original Features + XGBoost Probs + Leaf Embeddings]   │
    └─────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
    ┌─────────────────────────────────────────────────────────────┐
    │                    LSTM Network                             │
    │            (Sequence learning on features)                  │
    └─────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
    ┌─────────────────────────────────────────────────────────────┐
    │                  FINAL PREDICTION                           │
    │              (Benign / Malicious)                           │
    └─────────────────────────────────────────────────────────────┘
    """
    
    def __init__(self, n_features=36, xgb_params=None, lstm_params=None):
        self.n_features = n_features
        self.xgb_model = None
        self.lstm_model = None
        self.scaler = StandardScaler()
        self.device = None
        
        # XGBoost parameters
        self.xgb_params = xgb_params or {
            'n_estimators': 100,
            'max_depth': 6,
            'learning_rate': 0.1,
            'random_state': 42,
            'use_label_encoder': False,
            'eval_metric': 'logloss'
        }
        
        # LSTM parameters
        self.lstm_params = lstm_params or {
            'hidden_size': 64,
            'num_layers': 2,
            'dropout': 0.3,
            'learning_rate': 0.001,
            'epochs': 50,
            'batch_size': 32,
            'patience': 15
        }
    
    def _create_lstm_model(self, input_size):
        """Create LSTM model for the hybrid architecture."""
        import torch
        import torch.nn as nn
        
        class HybridLSTM(nn.Module):
            def __init__(self, input_size, hidden_size, num_layers, dropout):
                super(HybridLSTM, self).__init__()
                
                self.hidden_size = hidden_size
                self.num_layers = num_layers
                
                # LSTM layer
                self.lstm = nn.LSTM(
                    input_size=1,
                    hidden_size=hidden_size,
                    num_layers=num_layers,
                    batch_first=True,
                    dropout=dropout if num_layers > 1 else 0,
                    bidirectional=True
                )
                
                # Attention mechanism
                self.attention = nn.Sequential(
                    nn.Linear(hidden_size * 2, hidden_size),
                    nn.Tanh(),
                    nn.Linear(hidden_size, 1),
                    nn.Softmax(dim=1)
                )
                
                # Classification head
                self.classifier = nn.Sequential(
                    nn.Linear(hidden_size * 2, 64),
                    nn.ReLU(),
                    nn.BatchNorm1d(64),
                    nn.Dropout(dropout),
                    nn.Linear(64, 32),
                    nn.ReLU(),
                    nn.Dropout(dropout),
                    nn.Linear(32, 1),
                    nn.Sigmoid()
                )
            
            def forward(self, x):
                # LSTM forward pass
                lstm_out, _ = self.lstm(x)
                
                # Attention weights
                attn_weights = self.attention(lstm_out)
                
                # Weighted sum of LSTM outputs
                context = torch.sum(attn_weights * lstm_out, dim=1)
                
                # Classification
                out = self.classifier(context)
                return out.squeeze()
        
        return HybridLSTM(
            input_size=input_size,
            hidden_size=self.lstm_params['hidden_size'],
            num_layers=self.lstm_params['num_layers'],
            dropout=self.lstm_params['dropout']
        )
    
    def fit(self, X_train, y_train, X_val, y_val):
        """Train the hybrid model."""
        import torch
        import torch.nn as nn
        import torch.optim as optim
        from torch.utils.data import DataLoader, TensorDataset
        import xgboost as xgb
        
        logger.info("="*60)
        logger.info("TRAINING HYBRID XGBOOST + LSTM MODEL")
        logger.info("="*60)
        
        # ==================== PHASE 1: Train XGBoost ====================
        logger.info("\n[PHASE 1] Training XGBoost base model...")
        
        # Scale features for XGBoost
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        # Train XGBoost
        self.xgb_model = xgb.XGBClassifier(**self.xgb_params)
        self.xgb_model.fit(
            X_train_scaled, y_train,
            eval_set=[(X_val_scaled, y_val)],
            verbose=False
        )
        
        # Get XGBoost predictions (probabilities)
        xgb_train_proba = self.xgb_model.predict_proba(X_train_scaled)
        xgb_val_proba = self.xgb_model.predict_proba(X_val_scaled)
        
        # Get leaf indices for embedding
        xgb_train_leaves = self.xgb_model.apply(X_train_scaled)
        xgb_val_leaves = self.xgb_model.apply(X_val_scaled)
        
        # Normalize leaf indices
        leaf_scaler = MinMaxScaler()
        xgb_train_leaves_norm = leaf_scaler.fit_transform(xgb_train_leaves)
        xgb_val_leaves_norm = leaf_scaler.transform(xgb_val_leaves)
        
        # XGBoost standalone performance
        xgb_val_pred = self.xgb_model.predict(X_val_scaled)
        xgb_val_acc = accuracy_score(y_val, xgb_val_pred)
        logger.info(f"XGBoost validation accuracy: {xgb_val_acc:.4f}")
        
        # ==================== PHASE 2: Prepare Hybrid Features ====================
        logger.info("\n[PHASE 2] Creating hybrid feature vectors...")
        
        # Combine: Original features + XGBoost probabilities + Leaf embeddings (subset)
        # Use only first 10 trees' leaf indices to avoid too many features
        n_leaf_features = min(10, xgb_train_leaves_norm.shape[1])
        
        X_train_hybrid = np.concatenate([
            X_train_scaled,                          # Original 36 features
            xgb_train_proba,                         # 2 probability features
            xgb_train_leaves_norm[:, :n_leaf_features]  # 10 leaf index features
        ], axis=1)
        
        X_val_hybrid = np.concatenate([
            X_val_scaled,
            xgb_val_proba,
            xgb_val_leaves_norm[:, :n_leaf_features]
        ], axis=1)
        
        hybrid_feature_size = X_train_hybrid.shape[1]
        logger.info(f"Hybrid feature size: {hybrid_feature_size} (36 + 2 + {n_leaf_features})")
        
        # ==================== PHASE 3: Train LSTM ====================
        logger.info("\n[PHASE 3] Training LSTM on hybrid features...")
        
        # Setup device
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        logger.info(f"Using device: {self.device}")
        
        # Reshape for LSTM: (batch, seq_len, features)
        X_train_lstm = X_train_hybrid.reshape(-1, hybrid_feature_size, 1)
        X_val_lstm = X_val_hybrid.reshape(-1, hybrid_feature_size, 1)
        
        # Convert to tensors
        X_train_t = torch.FloatTensor(X_train_lstm).to(self.device)
        y_train_t = torch.FloatTensor(y_train).to(self.device)
        X_val_t = torch.FloatTensor(X_val_lstm).to(self.device)
        y_val_t = torch.FloatTensor(y_val).to(self.device)
        
        # Create dataloaders
        train_dataset = TensorDataset(X_train_t, y_train_t)
        val_dataset = TensorDataset(X_val_t, y_val_t)
        
        batch_size = self.lstm_params['batch_size']
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size)
        
        # Create and train LSTM
        self.lstm_model = self._create_lstm_model(hybrid_feature_size).to(self.device)
        
        criterion = nn.BCELoss()
        optimizer = optim.Adam(
            self.lstm_model.parameters(), 
            lr=self.lstm_params['learning_rate'],
            weight_decay=1e-5
        )
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, patience=5, factor=0.5, min_lr=1e-6
        )
        
        # Training loop
        best_val_loss = float('inf')
        best_val_acc = 0
        patience_counter = 0
        history = {'train_loss': [], 'val_loss': [], 'val_acc': []}
        
        for epoch in range(self.lstm_params['epochs']):
            # Training
            self.lstm_model.train()
            train_loss = 0
            for X_batch, y_batch in train_loader:
                optimizer.zero_grad()
                outputs = self.lstm_model(X_batch)
                loss = criterion(outputs, y_batch)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.lstm_model.parameters(), 1.0)
                optimizer.step()
                train_loss += loss.item()
            train_loss /= len(train_loader)
            
            # Validation
            self.lstm_model.eval()
            val_loss = 0
            val_correct = 0
            val_total = 0
            
            with torch.no_grad():
                for X_batch, y_batch in val_loader:
                    outputs = self.lstm_model(X_batch)
                    loss = criterion(outputs, y_batch)
                    val_loss += loss.item()
                    
                    predicted = (outputs > 0.5).float()
                    val_total += y_batch.size(0)
                    val_correct += (predicted == y_batch).sum().item()
            
            val_loss /= len(val_loader)
            val_acc = val_correct / val_total
            
            history['train_loss'].append(train_loss)
            history['val_loss'].append(val_loss)
            history['val_acc'].append(val_acc)
            
            scheduler.step(val_loss)
            
            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch {epoch+1}/{self.lstm_params['epochs']} - "
                          f"Train Loss: {train_loss:.4f}, Val Loss: {val_loss:.4f}, "
                          f"Val Acc: {val_acc:.4f}")
            
            # Early stopping with best model saving
            if val_acc > best_val_acc:
                best_val_acc = val_acc
                best_val_loss = val_loss
                patience_counter = 0
                best_model_state = self.lstm_model.state_dict().copy()
            else:
                patience_counter += 1
                if patience_counter >= self.lstm_params['patience']:
                    logger.info(f"Early stopping at epoch {epoch+1}")
                    break
        
        # Load best model
        self.lstm_model.load_state_dict(best_model_state)
        logger.info(f"Best validation accuracy: {best_val_acc:.4f}")
        
        # Store training history
        self.history = history
        self.leaf_scaler = leaf_scaler
        self.n_leaf_features = n_leaf_features
        
        return self
    
    def predict(self, X):
        """Make predictions using the hybrid model."""
        import torch
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Get XGBoost outputs
        xgb_proba = self.xgb_model.predict_proba(X_scaled)
        xgb_leaves = self.xgb_model.apply(X_scaled)
        xgb_leaves_norm = self.leaf_scaler.transform(xgb_leaves)
        
        # Create hybrid features
        X_hybrid = np.concatenate([
            X_scaled,
            xgb_proba,
            xgb_leaves_norm[:, :self.n_leaf_features]
        ], axis=1)
        
        # Reshape for LSTM
        X_lstm = X_hybrid.reshape(-1, X_hybrid.shape[1], 1)
        X_tensor = torch.FloatTensor(X_lstm).to(self.device)
        
        # Get LSTM predictions
        self.lstm_model.eval()
        with torch.no_grad():
            outputs = self.lstm_model(X_tensor)
            predictions = (outputs > 0.5).float().cpu().numpy()
        
        return predictions
    
    def predict_proba(self, X):
        """Get prediction probabilities."""
        import torch
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Get XGBoost outputs
        xgb_proba = self.xgb_model.predict_proba(X_scaled)
        xgb_leaves = self.xgb_model.apply(X_scaled)
        xgb_leaves_norm = self.leaf_scaler.transform(xgb_leaves)
        
        # Create hybrid features
        X_hybrid = np.concatenate([
            X_scaled,
            xgb_proba,
            xgb_leaves_norm[:, :self.n_leaf_features]
        ], axis=1)
        
        # Reshape for LSTM
        X_lstm = X_hybrid.reshape(-1, X_hybrid.shape[1], 1)
        X_tensor = torch.FloatTensor(X_lstm).to(self.device)
        
        # Get LSTM probabilities
        self.lstm_model.eval()
        with torch.no_grad():
            proba = self.lstm_model(X_tensor).cpu().numpy()
        
        return proba


def load_parsed_data(data_dir: Path):
    """Load the pre-parsed trace data."""
    benign_path = data_dir / "processed" / "benign_parsed.json"
    malicious_path = data_dir / "processed" / "malicious_parsed.json"
    
    logger.info(f"Loading benign data from {benign_path}")
    with open(benign_path, 'r') as f:
        benign_data = json.load(f)
    
    logger.info(f"Loading malicious data from {malicious_path}")
    with open(malicious_path, 'r') as f:
        malicious_data = json.load(f)
    
    logger.info(f"Loaded {len(benign_data)} benign and {len(malicious_data)} malicious samples")
    return benign_data, malicious_data


def main():
    """Main function to train and evaluate hybrid model."""
    print("\n" + "="*70)
    print("HYBRID XGBOOST + LSTM ENSEMBLE MODEL")
    print("Malware Detection using 36 QUT-DV25 Features")
    print("="*70)
    
    # Setup paths
    data_dir = project_root / "data"
    output_dir = project_root / "trained_models" / "hybrid_model"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Try to load pre-extracted QUT features first
    qut_features_dir = project_root / "processed" / "qut_features"
    
    if (qut_features_dir / "X_train.npy").exists():
        logger.info("\n[STEP 1] Loading pre-extracted QUT features...")
        X_train = np.load(qut_features_dir / "X_train.npy")
        X_val = np.load(qut_features_dir / "X_val.npy")
        X_test = np.load(qut_features_dir / "X_test.npy")
        y_train = np.load(qut_features_dir / "y_train.npy")
        y_val = np.load(qut_features_dir / "y_val.npy")
        y_test = np.load(qut_features_dir / "y_test.npy")
        
        with open(qut_features_dir / "feature_names.json", 'r') as f:
            feature_names = json.load(f)
        
        logger.info(f"Loaded features - Train: {len(y_train)}, Val: {len(y_val)}, Test: {len(y_test)}")
        logger.info(f"Number of features: {len(feature_names)}")
    else:
        # Load and extract features from raw data
        logger.info("\n[STEP 1] Loading and extracting features...")
        benign_data, malicious_data = load_parsed_data(data_dir)
        
        X, y, feature_names, _ = extract_qut_features_from_parsed_data(
            benign_data, malicious_data
        )
        
        logger.info(f"Feature matrix shape: {X.shape}")
        logger.info(f"Number of features: {len(feature_names)}")
        
        # Split data
        logger.info("\n[STEP 2] Splitting data...")
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
        )
    
    logger.info(f"Train: {len(y_train)} | Val: {len(y_val)} | Test: {len(y_test)}")
    
    # Train hybrid model
    logger.info("\n[STEP 3] Training hybrid model...")
    hybrid_model = HybridXGBoostLSTM(n_features=36)
    hybrid_model.fit(X_train, y_train, X_val, y_val)
    
    # Evaluate on test set
    logger.info("\n[STEP 4] Evaluating on test set...")
    y_pred = hybrid_model.predict(X_test)
    y_pred_proba = hybrid_model.predict_proba(X_test)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_pred_proba)
    
    # Also get individual model performances for comparison
    # XGBoost standalone
    X_test_scaled = hybrid_model.scaler.transform(X_test)
    xgb_pred = hybrid_model.xgb_model.predict(X_test_scaled)
    xgb_proba = hybrid_model.xgb_model.predict_proba(X_test_scaled)[:, 1]
    xgb_accuracy = accuracy_score(y_test, xgb_pred)
    xgb_precision = precision_score(y_test, xgb_pred)
    xgb_recall = recall_score(y_test, xgb_pred)
    xgb_f1 = f1_score(y_test, xgb_pred)
    xgb_auc = roc_auc_score(y_test, xgb_proba)
    
    # Results
    results = {
        'hybrid': {
            'model': 'Hybrid XGBoost+LSTM',
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'auc_roc': float(auc),
        },
        'xgboost_standalone': {
            'model': 'XGBoost (Standalone)',
            'accuracy': float(xgb_accuracy),
            'precision': float(xgb_precision),
            'recall': float(xgb_recall),
            'f1_score': float(xgb_f1),
            'auc_roc': float(xgb_auc),
        },
        'metadata': {
            'features': '36 QUT Features',
            'train_samples': len(y_train),
            'val_samples': len(y_val),
            'test_samples': len(y_test),
            'timestamp': datetime.now().isoformat()
        }
    }
    
    # Print results
    print("\n" + "="*70)
    print("RESULTS: HYBRID MODEL vs STANDALONE MODELS")
    print("="*70)
    
    print("\n┌" + "─"*68 + "┐")
    print("│" + " HYBRID XGBOOST + LSTM RESULTS".center(68) + "│")
    print("├" + "─"*68 + "┤")
    print(f"│  Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)".ljust(69) + "│")
    print(f"│  Precision: {precision:.4f}".ljust(69) + "│")
    print(f"│  Recall:    {recall:.4f}".ljust(69) + "│")
    print(f"│  F1 Score:  {f1:.4f}".ljust(69) + "│")
    print(f"│  AUC-ROC:   {auc:.4f}".ljust(69) + "│")
    print("└" + "─"*68 + "┘")
    
    print("\n" + "="*70)
    print("MODEL COMPARISON (Test Set)")
    print("="*70)
    print(f"{'Metric':<15} {'XGBoost':>15} {'Hybrid XGB+LSTM':>20} {'Improvement':>15}")
    print("-"*70)
    print(f"{'Accuracy':<15} {xgb_accuracy*100:>14.2f}% {accuracy*100:>19.2f}% {(accuracy-xgb_accuracy)*100:>+14.2f}%")
    print(f"{'Precision':<15} {xgb_precision:>15.4f} {precision:>20.4f} {precision-xgb_precision:>+15.4f}")
    print(f"{'Recall':<15} {xgb_recall:>15.4f} {recall:>20.4f} {recall-xgb_recall:>+15.4f}")
    print(f"{'F1 Score':<15} {xgb_f1:>15.4f} {f1:>20.4f} {f1-xgb_f1:>+15.4f}")
    print(f"{'AUC-ROC':<15} {xgb_auc:>15.4f} {auc:>20.4f} {auc-xgb_auc:>+15.4f}")
    print("="*70)
    
    # Confusion Matrix
    print("\nConfusion Matrix (Hybrid Model):")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                    Predicted")
    print(f"                    Benign  Malicious")
    print(f"Actual Benign         {int(cm[0,0]):4d}      {int(cm[0,1]):4d}")
    print(f"Actual Malicious      {int(cm[1,0]):4d}      {int(cm[1,1]):4d}")
    
    print("\n" + classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
    
    # Save results
    with open(output_dir / "hybrid_results.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    with open(output_dir / "training_history.json", 'w') as f:
        json.dump(hybrid_model.history, f, indent=2)
    
    # Save models
    import torch
    torch.save(hybrid_model.lstm_model.state_dict(), output_dir / "hybrid_lstm.pt")
    hybrid_model.xgb_model.save_model(str(output_dir / "hybrid_xgboost.json"))
    
    logger.info(f"\nResults saved to: {output_dir}")
    
    # Print explanation
    print("\n" + "="*70)
    print("WHY HYBRID APPROACH IS PREFERRED")
    print("="*70)
    print("""
┌─────────────────────────────────────────────────────────────────────┐
│                    ADVANTAGES OF HYBRID MODEL                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. COMPLEMENTARY STRENGTHS                                          │
│     • XGBoost: Excellent at feature interactions & tabular data     │
│     • LSTM: Captures sequential patterns & temporal dependencies    │
│     • Combined: Best of both worlds                                  │
│                                                                      │
│  2. ERROR CORRECTION                                                 │
│     • LSTM can correct XGBoost's misclassifications                 │
│     • Uses XGBoost confidence scores to guide decisions             │
│     • Leaf indices provide decision path information                │
│                                                                      │
│  3. REDUCED BIAS                                                     │
│     • Single models have inherent biases                            │
│     • Ensemble reduces individual model weaknesses                  │
│     • More robust to different attack patterns                      │
│                                                                      │
│  4. FEATURE ENRICHMENT                                               │
│     • XGBoost outputs add 12 new features (probs + leaves)          │
│     • LSTM learns from enriched representation                      │
│     • Better captures complex malware behaviors                     │
│                                                                      │
│  5. BETTER GENERALIZATION                                            │
│     • Less prone to overfitting than single models                  │
│     • More stable predictions across different samples              │
│     • Improved performance on edge cases                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
""")
    
    return results


if __name__ == "__main__":
    results = main()
