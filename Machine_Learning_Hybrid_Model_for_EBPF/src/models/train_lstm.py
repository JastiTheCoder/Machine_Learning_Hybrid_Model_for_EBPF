"""
LSTM/BiLSTM Model for Syscall Sequence Classification

This model treats syscall traces as sequences and uses:
1. Embedding layer to encode syscall types
2. BiLSTM to capture temporal patterns
3. Attention mechanism (optional) to focus on critical events
4. Dense layers for classification

Advantages over tree models:
- Captures sequential patterns (order matters)
- Can detect anomalous syscall orderings
- Better at finding complex behavioral patterns
"""

import os
import sys
import argparse
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from collections import Counter

# PyTorch imports
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from torch.optim import Adam
from torch.optim.lr_scheduler import ReduceLROnPlateau

# Metrics
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    roc_auc_score,
    precision_recall_fscore_support
)
import matplotlib.pyplot as plt
import seaborn as sns

# Add project root
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.utils.helpers import (
    setup_logging, 
    load_config, 
    load_json,
    save_json,
    ensure_dir,
    Timer
)


class SyscallVocabulary:
    """
    Vocabulary for mapping syscall tokens to indices.
    """
    
    PAD_TOKEN = '<PAD>'
    UNK_TOKEN = '<UNK>'
    
    def __init__(self, min_freq: int = 1):
        self.min_freq = min_freq
        self.token2idx = {}
        self.idx2token = {}
        self.token_freq = Counter()
        
    def build(self, sequences: List[List[str]]):
        """Build vocabulary from sequences."""
        # Count frequencies
        for seq in sequences:
            self.token_freq.update(seq)
        
        # Create mappings
        self.token2idx = {
            self.PAD_TOKEN: 0,
            self.UNK_TOKEN: 1
        }
        
        idx = 2
        for token, freq in self.token_freq.most_common():
            if freq >= self.min_freq:
                self.token2idx[token] = idx
                idx += 1
        
        self.idx2token = {v: k for k, v in self.token2idx.items()}
        
    def encode(self, sequence: List[str]) -> List[int]:
        """Convert tokens to indices."""
        return [
            self.token2idx.get(token, self.token2idx[self.UNK_TOKEN])
            for token in sequence
        ]
    
    def decode(self, indices: List[int]) -> List[str]:
        """Convert indices back to tokens."""
        return [self.idx2token.get(idx, self.UNK_TOKEN) for idx in indices]
    
    def __len__(self):
        return len(self.token2idx)
    
    def save(self, filepath: str):
        """Save vocabulary to file."""
        save_json({
            'token2idx': self.token2idx,
            'min_freq': self.min_freq
        }, filepath)
    
    @classmethod
    def load(cls, filepath: str) -> 'SyscallVocabulary':
        """Load vocabulary from file."""
        data = load_json(filepath)
        vocab = cls(min_freq=data['min_freq'])
        vocab.token2idx = data['token2idx']
        vocab.idx2token = {int(v): k for k, v in vocab.token2idx.items()}
        return vocab


class SyscallDataset(Dataset):
    """
    PyTorch Dataset for syscall sequences.
    """
    
    def __init__(
        self, 
        sequences: List[List[str]], 
        labels: List[int],
        vocab: SyscallVocabulary,
        max_length: int = 500
    ):
        self.sequences = sequences
        self.labels = labels
        self.vocab = vocab
        self.max_length = max_length
        
    def __len__(self):
        return len(self.sequences)
    
    def __getitem__(self, idx):
        seq = self.sequences[idx]
        label = self.labels[idx]
        
        # Encode
        encoded = self.vocab.encode(seq)
        
        # Truncate or pad
        if len(encoded) > self.max_length:
            encoded = encoded[:self.max_length]
        else:
            encoded = encoded + [0] * (self.max_length - len(encoded))
        
        return {
            'input_ids': torch.tensor(encoded, dtype=torch.long),
            'label': torch.tensor(label, dtype=torch.long),
            'length': min(len(seq), self.max_length)
        }


class Attention(nn.Module):
    """
    Simple attention mechanism for LSTM outputs.
    """
    
    def __init__(self, hidden_dim: int):
        super().__init__()
        self.attention = nn.Linear(hidden_dim, 1)
        
    def forward(self, lstm_output, lengths=None):
        # lstm_output: (batch, seq_len, hidden_dim)
        attention_weights = self.attention(lstm_output)  # (batch, seq_len, 1)
        attention_weights = F.softmax(attention_weights, dim=1)
        
        # Weighted sum
        context = torch.sum(attention_weights * lstm_output, dim=1)  # (batch, hidden_dim)
        
        return context, attention_weights.squeeze(-1)


class BiLSTMClassifier(nn.Module):
    """
    Bidirectional LSTM classifier for syscall sequences.
    
    Architecture:
    1. Embedding layer
    2. BiLSTM (captures forward and backward context)
    3. Attention (optional)
    4. Dense layers
    5. Output (binary classification)
    """
    
    def __init__(
        self,
        vocab_size: int,
        embedding_dim: int = 64,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.3,
        use_attention: bool = True,
        num_classes: int = 2
    ):
        super().__init__()
        
        self.embedding = nn.Embedding(
            vocab_size, 
            embedding_dim, 
            padding_idx=0
        )
        
        self.lstm = nn.LSTM(
            embedding_dim,
            hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=True
        )
        
        self.use_attention = use_attention
        if use_attention:
            self.attention = Attention(hidden_dim * 2)  # *2 for bidirectional
        
        self.dropout = nn.Dropout(dropout)
        
        # Classification head
        self.fc1 = nn.Linear(hidden_dim * 2, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, num_classes)
        
    def forward(self, input_ids, lengths=None):
        # Embedding
        embedded = self.embedding(input_ids)  # (batch, seq_len, embed_dim)
        embedded = self.dropout(embedded)
        
        # LSTM
        lstm_out, (hidden, cell) = self.lstm(embedded)
        # lstm_out: (batch, seq_len, hidden_dim * 2)
        
        if self.use_attention:
            context, _ = self.attention(lstm_out, lengths)
        else:
            # Use final hidden states
            # Concatenate forward and backward
            context = torch.cat([hidden[-2], hidden[-1]], dim=1)
        
        # Classification
        x = self.dropout(context)
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        logits = self.fc2(x)
        
        return logits


class LSTMTrainer:
    """
    Trainer class for BiLSTM model.
    """
    
    def __init__(self, config: dict, logger=None, device: str = None):
        self.config = config
        self.logger = logger or setup_logging(name='lstm_trainer')
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        
        self.model = None
        self.vocab = None
        self.optimizer = None
        self.scheduler = None
        self.criterion = None
        
        self.logger.info(f"Using device: {self.device}")
        
    def build_vocab(self, train_sequences: List[List[str]]) -> SyscallVocabulary:
        """Build vocabulary from training sequences."""
        self.vocab = SyscallVocabulary(min_freq=2)
        self.vocab.build(train_sequences)
        self.logger.info(f"Vocabulary size: {len(self.vocab)}")
        return self.vocab
        
    def create_model(self) -> BiLSTMClassifier:
        """Create the BiLSTM model."""
        lstm_config = self.config.get('lstm', {})
        
        self.model = BiLSTMClassifier(
            vocab_size=len(self.vocab),
            embedding_dim=lstm_config.get('embedding_dim', 64),
            hidden_dim=lstm_config.get('hidden_dim', 128),
            num_layers=lstm_config.get('num_layers', 2),
            dropout=lstm_config.get('dropout', 0.3),
            use_attention=True
        ).to(self.device)
        
        # Count parameters
        n_params = sum(p.numel() for p in self.model.parameters() if p.requires_grad)
        self.logger.info(f"Model parameters: {n_params:,}")
        
        return self.model
    
    def create_dataloader(
        self, 
        sequences: List[List[str]], 
        labels: List[int],
        batch_size: int = 32,
        shuffle: bool = True
    ) -> DataLoader:
        """Create DataLoader from sequences."""
        max_length = self.config.get('lstm', {}).get('max_sequence_length', 500)
        
        dataset = SyscallDataset(
            sequences=sequences,
            labels=labels,
            vocab=self.vocab,
            max_length=max_length
        )
        
        return DataLoader(
            dataset,
            batch_size=batch_size,
            shuffle=shuffle,
            num_workers=0
        )
    
    def train(
        self,
        train_sequences: List[List[str]],
        train_labels: List[int],
        val_sequences: List[List[str]] = None,
        val_labels: List[int] = None,
        epochs: int = 50
    ) -> dict:
        """
        Train the model.
        
        Returns:
            Training history
        """
        train_config = self.config.get('training', {})
        batch_size = train_config.get('batch_size', 32)
        lr = train_config.get('learning_rate', 0.001)
        patience = train_config.get('early_stopping_patience', 10)
        
        # Build vocab and model
        self.build_vocab(train_sequences)
        self.create_model()
        
        # Create dataloaders
        train_loader = self.create_dataloader(
            train_sequences, train_labels, batch_size, shuffle=True
        )
        
        val_loader = None
        if val_sequences and val_labels:
            val_loader = self.create_dataloader(
                val_sequences, val_labels, batch_size, shuffle=False
            )
        
        # Loss with class weights
        n_pos = sum(train_labels)
        n_neg = len(train_labels) - n_pos
        pos_weight = torch.tensor([n_neg / n_pos if n_pos > 0 else 1.0]).to(self.device)
        self.criterion = nn.CrossEntropyLoss(
            weight=torch.tensor([1.0, pos_weight.item()]).to(self.device)
        )
        
        # Optimizer and scheduler
        self.optimizer = Adam(self.model.parameters(), lr=lr)
        self.scheduler = ReduceLROnPlateau(
            self.optimizer, mode='min', factor=0.5, patience=3
        )
        
        # Training loop
        history = {
            'train_loss': [], 'train_acc': [],
            'val_loss': [], 'val_acc': []
        }
        
        best_val_loss = float('inf')
        patience_counter = 0
        best_model_state = None
        
        for epoch in range(epochs):
            # Train
            train_loss, train_acc = self._train_epoch(train_loader)
            history['train_loss'].append(train_loss)
            history['train_acc'].append(train_acc)
            
            # Validate
            if val_loader:
                val_loss, val_acc = self._validate(val_loader)
                history['val_loss'].append(val_loss)
                history['val_acc'].append(val_acc)
                
                self.scheduler.step(val_loss)
                
                # Early stopping
                if val_loss < best_val_loss:
                    best_val_loss = val_loss
                    patience_counter = 0
                    best_model_state = self.model.state_dict().copy()
                else:
                    patience_counter += 1
                
                self.logger.info(
                    f"Epoch {epoch+1}/{epochs} - "
                    f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f}, "
                    f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}"
                )
                
                if patience_counter >= patience:
                    self.logger.info(f"Early stopping at epoch {epoch+1}")
                    break
            else:
                self.logger.info(
                    f"Epoch {epoch+1}/{epochs} - "
                    f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f}"
                )
        
        # Load best model
        if best_model_state:
            self.model.load_state_dict(best_model_state)
        
        return history
    
    def _train_epoch(self, dataloader: DataLoader) -> Tuple[float, float]:
        """Train for one epoch."""
        self.model.train()
        total_loss = 0
        correct = 0
        total = 0
        
        for batch in dataloader:
            input_ids = batch['input_ids'].to(self.device)
            labels = batch['label'].to(self.device)
            
            self.optimizer.zero_grad()
            
            logits = self.model(input_ids)
            loss = self.criterion(logits, labels)
            
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
            self.optimizer.step()
            
            total_loss += loss.item()
            preds = torch.argmax(logits, dim=1)
            correct += (preds == labels).sum().item()
            total += labels.size(0)
        
        return total_loss / len(dataloader), correct / total
    
    def _validate(self, dataloader: DataLoader) -> Tuple[float, float]:
        """Validate the model."""
        self.model.eval()
        total_loss = 0
        correct = 0
        total = 0
        
        with torch.no_grad():
            for batch in dataloader:
                input_ids = batch['input_ids'].to(self.device)
                labels = batch['label'].to(self.device)
                
                logits = self.model(input_ids)
                loss = self.criterion(logits, labels)
                
                total_loss += loss.item()
                preds = torch.argmax(logits, dim=1)
                correct += (preds == labels).sum().item()
                total += labels.size(0)
        
        return total_loss / len(dataloader), correct / total
    
    def evaluate(
        self, 
        test_sequences: List[List[str]], 
        test_labels: List[int],
        output_dir: str = None
    ) -> dict:
        """Evaluate on test set."""
        batch_size = self.config.get('training', {}).get('batch_size', 32)
        test_loader = self.create_dataloader(
            test_sequences, test_labels, batch_size, shuffle=False
        )
        
        self.model.eval()
        all_preds = []
        all_probs = []
        all_labels = []
        
        with torch.no_grad():
            for batch in test_loader:
                input_ids = batch['input_ids'].to(self.device)
                labels = batch['label']
                
                logits = self.model(input_ids)
                probs = F.softmax(logits, dim=1)
                preds = torch.argmax(logits, dim=1)
                
                all_preds.extend(preds.cpu().numpy())
                all_probs.extend(probs[:, 1].cpu().numpy())
                all_labels.extend(labels.numpy())
        
        # Calculate metrics
        y_test = np.array(all_labels)
        y_pred = np.array(all_preds)
        y_prob = np.array(all_probs)
        
        report = classification_report(y_test, y_pred, output_dict=True)
        conf_matrix = confusion_matrix(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_prob)
        
        results = {
            'classification_report': report,
            'confusion_matrix': conf_matrix.tolist(),
            'roc_auc': float(roc_auc),
            'accuracy': float(report['accuracy']),
            'precision': float(report['1']['precision']),
            'recall': float(report['1']['recall']),
            'f1': float(report['1']['f1-score']),
        }
        
        self.logger.info("\n" + "="*50)
        self.logger.info("TEST SET EVALUATION (BiLSTM)")
        self.logger.info("="*50)
        self.logger.info(f"Accuracy:  {results['accuracy']:.4f}")
        self.logger.info(f"Precision: {results['precision']:.4f}")
        self.logger.info(f"Recall:    {results['recall']:.4f}")
        self.logger.info(f"F1 Score:  {results['f1']:.4f}")
        self.logger.info(f"ROC-AUC:   {results['roc_auc']:.4f}")
        
        # Save plots
        if output_dir:
            self._save_plots(conf_matrix, output_dir)
        
        return results
    
    def _save_plots(self, conf_matrix, output_dir):
        """Save evaluation plots."""
        ensure_dir(output_dir)
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
                    xticklabels=['Benign', 'Malicious'],
                    yticklabels=['Benign', 'Malicious'])
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('Confusion Matrix - BiLSTM')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'lstm_confusion_matrix.png'), dpi=150)
        plt.close()
    
    def save_model(self, filepath: str):
        """Save model and vocabulary."""
        ensure_dir(os.path.dirname(filepath))
        
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'vocab': {
                'token2idx': self.vocab.token2idx,
                'min_freq': self.vocab.min_freq
            },
            'config': self.config
        }, filepath)
        
        self.logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load model and vocabulary."""
        checkpoint = torch.load(filepath, map_location=self.device)
        
        # Restore vocab
        self.vocab = SyscallVocabulary(min_freq=checkpoint['vocab']['min_freq'])
        self.vocab.token2idx = checkpoint['vocab']['token2idx']
        self.vocab.idx2token = {int(v): k for k, v in self.vocab.token2idx.items()}
        
        # Restore config and model
        self.config = checkpoint['config']
        self.create_model()
        self.model.load_state_dict(checkpoint['model_state_dict'])
        
        self.logger.info(f"Model loaded from {filepath}")


def main():
    parser = argparse.ArgumentParser(description='Train BiLSTM model')
    parser.add_argument('--config', type=str, default='configs/config.yaml',
                        help='Path to config file')
    parser.add_argument('--epochs', type=int, default=None,
                        help='Override number of epochs')
    args = parser.parse_args()
    
    # Setup
    logger = setup_logging(name='train_lstm')
    config = load_config(args.config)
    
    processed_dir = config['data']['processed_dir']
    features_dir = os.path.join(processed_dir, 'features')
    models_dir = 'trained_models'
    
    logger.info("="*60)
    logger.info("BiLSTM Model Training")
    logger.info("="*60)
    
    # Load sequence data
    logger.info("Loading sequence data...")
    
    train_data = load_json(os.path.join(features_dir, 'sequences_train.json'))
    val_data = load_json(os.path.join(features_dir, 'sequences_val.json'))
    test_data = load_json(os.path.join(features_dir, 'sequences_test.json'))
    
    train_sequences = train_data['sequences']
    train_labels = train_data['labels']
    val_sequences = val_data['sequences']
    val_labels = val_data['labels']
    test_sequences = test_data['sequences']
    test_labels = test_data['labels']
    
    logger.info(f"Train: {len(train_sequences)}, Val: {len(val_sequences)}, Test: {len(test_sequences)}")
    
    # Initialize trainer
    trainer = LSTMTrainer(config['models'], logger)
    
    # Train
    epochs = args.epochs or config['models']['training']['epochs']
    with Timer("Training BiLSTM"):
        history = trainer.train(
            train_sequences, train_labels,
            val_sequences, val_labels,
            epochs=epochs
        )
    
    # Evaluate
    results = trainer.evaluate(
        test_sequences, test_labels,
        output_dir=os.path.join(models_dir, 'evaluation')
    )
    
    # Save model
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_path = os.path.join(models_dir, f'lstm_{timestamp}.pt')
    trainer.save_model(model_path)
    trainer.save_model(os.path.join(models_dir, 'lstm_latest.pt'))
    
    # Save results
    save_json(results, os.path.join(models_dir, 'lstm_results.json'))
    save_json(history, os.path.join(models_dir, 'lstm_history.json'))
    
    logger.info("="*60)
    logger.info("Training complete!")
    logger.info("="*60)


if __name__ == '__main__':
    main()
