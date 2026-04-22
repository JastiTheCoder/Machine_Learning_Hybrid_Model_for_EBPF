"""
XGBoost Model Training for eBPF Malware Detection

XGBoost is our primary model because:
1. Works well with tabular/structured data
2. Handles imbalanced classes well
3. Provides feature importance
4. Fast inference for real-time detection
5. No need for massive training data
"""

import os
import sys
import argparse
import numpy as np
import pickle
from pathlib import Path
from datetime import datetime

# ML imports
from xgboost import XGBClassifier
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    roc_auc_score,
    precision_recall_curve,
    average_precision_score
)
from sklearn.model_selection import cross_val_score, StratifiedKFold
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


class XGBoostTrainer:
    """
    XGBoost model trainer with:
    - Hyperparameter configuration
    - Cross-validation
    - Feature importance analysis
    - Model evaluation and visualization
    """
    
    def __init__(self, config: dict, logger=None):
        """
        Initialize trainer.
        
        Args:
            config: Model configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or setup_logging(name='xgboost_trainer')
        self.model = None
        self.feature_names = None
        
    def create_model(self, scale_pos_weight: float = 1.0) -> XGBClassifier:
        """
        Create XGBoost classifier with configured parameters.
        
        Args:
            scale_pos_weight: Weight for positive class (for imbalanced data)
        """
        xgb_config = self.config.get('xgboost', {})
        
        self.model = XGBClassifier(
            n_estimators=xgb_config.get('n_estimators', 200),
            max_depth=xgb_config.get('max_depth', 8),
            learning_rate=xgb_config.get('learning_rate', 0.1),
            subsample=xgb_config.get('subsample', 0.8),
            colsample_bytree=xgb_config.get('colsample_bytree', 0.8),
            min_child_weight=xgb_config.get('min_child_weight', 1),
            gamma=xgb_config.get('gamma', 0),
            reg_alpha=xgb_config.get('reg_alpha', 0.1),
            reg_lambda=xgb_config.get('reg_lambda', 1.0),
            scale_pos_weight=scale_pos_weight,
            objective='binary:logistic',
            eval_metric='auc',
            use_label_encoder=False,
            random_state=42,
            n_jobs=-1
        )
        
        return self.model
    
    def train(
        self, 
        X_train: np.ndarray, 
        y_train: np.ndarray,
        X_val: np.ndarray = None,
        y_val: np.ndarray = None,
        feature_names: list = None
    ):
        """
        Train the XGBoost model.
        
        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features (optional)
            y_val: Validation labels (optional)
            feature_names: List of feature names
        """
        self.feature_names = feature_names
        
        # Calculate class weight for imbalanced data
        n_neg = np.sum(y_train == 0)
        n_pos = np.sum(y_train == 1)
        scale_pos_weight = n_neg / n_pos if n_pos > 0 else 1.0
        
        self.logger.info(f"Class distribution - Benign: {n_neg}, Malicious: {n_pos}")
        self.logger.info(f"Using scale_pos_weight: {scale_pos_weight:.2f}")
        
        # Create model
        self.create_model(scale_pos_weight=scale_pos_weight)
        
        # Prepare eval set
        eval_set = [(X_train, y_train)]
        if X_val is not None and y_val is not None:
            eval_set.append((X_val, y_val))
        
        # Train
        self.logger.info("Training XGBoost model...")
        self.model.fit(
            X_train, y_train,
            eval_set=eval_set,
            verbose=True
        )
        
        self.logger.info("Training complete!")
        
    def cross_validate(
        self, 
        X: np.ndarray, 
        y: np.ndarray, 
        n_folds: int = 5
    ) -> dict:
        """
        Perform cross-validation.
        
        Args:
            X: Features
            y: Labels
            n_folds: Number of CV folds
            
        Returns:
            Dictionary with CV results
        """
        if self.model is None:
            self.create_model()
        
        self.logger.info(f"Running {n_folds}-fold cross-validation...")
        
        cv = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)
        
        # Multiple metrics
        scoring = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
        cv_results = {}
        
        for metric in scoring:
            scores = cross_val_score(self.model, X, y, cv=cv, scoring=metric)
            cv_results[metric] = {
                'mean': float(scores.mean()),
                'std': float(scores.std()),
                'scores': scores.tolist()
            }
            self.logger.info(f"  {metric}: {scores.mean():.4f} (+/- {scores.std()*2:.4f})")
        
        return cv_results
    
    def evaluate(
        self, 
        X_test: np.ndarray, 
        y_test: np.ndarray,
        output_dir: str = None
    ) -> dict:
        """
        Evaluate model on test set.
        
        Args:
            X_test: Test features
            y_test: Test labels
            output_dir: Directory to save plots
            
        Returns:
            Dictionary with evaluation metrics
        """
        if self.model is None:
            raise ValueError("Model not trained yet!")
        
        # Predictions
        y_pred = self.model.predict(X_test)
        y_prob = self.model.predict_proba(X_test)[:, 1]
        
        # Metrics
        report = classification_report(y_test, y_pred, output_dict=True)
        conf_matrix = confusion_matrix(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_prob)
        avg_precision = average_precision_score(y_test, y_prob)
        
        results = {
            'classification_report': report,
            'confusion_matrix': conf_matrix.tolist(),
            'roc_auc': float(roc_auc),
            'average_precision': float(avg_precision),
            'accuracy': float(report['accuracy']),
            'precision': float(report['1']['precision']),
            'recall': float(report['1']['recall']),
            'f1': float(report['1']['f1-score']),
        }
        
        self.logger.info("\n" + "="*50)
        self.logger.info("TEST SET EVALUATION")
        self.logger.info("="*50)
        self.logger.info(f"Accuracy:  {results['accuracy']:.4f}")
        self.logger.info(f"Precision: {results['precision']:.4f}")
        self.logger.info(f"Recall:    {results['recall']:.4f}")
        self.logger.info(f"F1 Score:  {results['f1']:.4f}")
        self.logger.info(f"ROC-AUC:   {results['roc_auc']:.4f}")
        self.logger.info(f"Avg Precision: {results['average_precision']:.4f}")
        self.logger.info("\nConfusion Matrix:")
        self.logger.info(f"  TN={conf_matrix[0,0]}, FP={conf_matrix[0,1]}")
        self.logger.info(f"  FN={conf_matrix[1,0]}, TP={conf_matrix[1,1]}")
        
        # Save plots
        if output_dir:
            self._save_evaluation_plots(
                y_test, y_pred, y_prob, 
                conf_matrix, output_dir
            )
        
        return results
    
    def _save_evaluation_plots(
        self, 
        y_test, y_pred, y_prob, 
        conf_matrix, output_dir
    ):
        """Save evaluation visualizations."""
        ensure_dir(output_dir)
        
        # 1. Confusion Matrix
        plt.figure(figsize=(8, 6))
        sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
                    xticklabels=['Benign', 'Malicious'],
                    yticklabels=['Benign', 'Malicious'])
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('Confusion Matrix - XGBoost')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'), dpi=150)
        plt.close()
        
        # 2. Feature Importance
        if self.feature_names:
            importances = self.model.feature_importances_
            indices = np.argsort(importances)[-20:]  # Top 20
            
            plt.figure(figsize=(10, 8))
            plt.barh(range(len(indices)), importances[indices])
            plt.yticks(range(len(indices)), [self.feature_names[i] for i in indices])
            plt.xlabel('Feature Importance')
            plt.title('Top 20 Most Important Features - XGBoost')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'feature_importance.png'), dpi=150)
            plt.close()
        
        # 3. Precision-Recall Curve
        precision, recall, thresholds = precision_recall_curve(y_test, y_prob)
        
        plt.figure(figsize=(8, 6))
        plt.plot(recall, precision, 'b-', linewidth=2)
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curve - XGBoost')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'precision_recall_curve.png'), dpi=150)
        plt.close()
        
        self.logger.info(f"Saved evaluation plots to {output_dir}")
    
    def get_feature_importance(self, top_n: int = 20) -> list:
        """
        Get top N most important features.
        
        Returns:
            List of (feature_name, importance) tuples
        """
        if self.model is None or self.feature_names is None:
            return []
        
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1][:top_n]
        
        return [
            (self.feature_names[i], float(importances[i])) 
            for i in indices
        ]
    
    def save_model(self, filepath: str):
        """Save trained model to file."""
        ensure_dir(os.path.dirname(filepath))
        
        save_data = {
            'model': self.model,
            'feature_names': self.feature_names,
            'config': self.config
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(save_data, f)
        
        self.logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load trained model from file."""
        with open(filepath, 'rb') as f:
            save_data = pickle.load(f)
        
        self.model = save_data['model']
        self.feature_names = save_data['feature_names']
        self.config = save_data.get('config', {})
        
        self.logger.info(f"Model loaded from {filepath}")


def main():
    parser = argparse.ArgumentParser(description='Train XGBoost model')
    parser.add_argument('--config', type=str, default='configs/config.yaml',
                        help='Path to config file')
    parser.add_argument('--cv', action='store_true',
                        help='Run cross-validation')
    args = parser.parse_args()
    
    # Setup
    logger = setup_logging(name='train_xgboost')
    config = load_config(args.config)
    
    processed_dir = config['data']['processed_dir']
    features_dir = os.path.join(processed_dir, 'features')
    models_dir = 'trained_models'
    
    logger.info("="*60)
    logger.info("XGBoost Model Training")
    logger.info("="*60)
    
    # Load data
    logger.info("Loading feature data...")
    
    X_train = np.load(os.path.join(features_dir, 'X_train.npy'))
    y_train = np.load(os.path.join(features_dir, 'y_train.npy'))
    X_val = np.load(os.path.join(features_dir, 'X_val.npy'))
    y_val = np.load(os.path.join(features_dir, 'y_val.npy'))
    X_test = np.load(os.path.join(features_dir, 'X_test.npy'))
    y_test = np.load(os.path.join(features_dir, 'y_test.npy'))
    feature_names = load_json(os.path.join(features_dir, 'feature_names.json'))
    
    logger.info(f"Train: {X_train.shape}, Val: {X_val.shape}, Test: {X_test.shape}")
    
    # Initialize trainer
    trainer = XGBoostTrainer(config['models'], logger)
    
    # Cross-validation (optional)
    if args.cv:
        X_all = np.vstack([X_train, X_val])
        y_all = np.concatenate([y_train, y_val])
        cv_results = trainer.cross_validate(X_all, y_all)
        save_json(cv_results, os.path.join(models_dir, 'cv_results.json'))
    
    # Train
    with Timer("Training XGBoost"):
        trainer.train(X_train, y_train, X_val, y_val, feature_names)
    
    # Evaluate
    results = trainer.evaluate(
        X_test, y_test, 
        output_dir=os.path.join(models_dir, 'evaluation')
    )
    
    # Feature importance
    importance = trainer.get_feature_importance(top_n=20)
    logger.info("\nTop 20 Important Features:")
    for i, (name, imp) in enumerate(importance, 1):
        logger.info(f"  {i:2d}. {name}: {imp:.4f}")
    
    # Save model
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_path = os.path.join(models_dir, f'xgboost_{timestamp}.pkl')
    trainer.save_model(model_path)
    
    # Save latest symlink/copy
    trainer.save_model(os.path.join(models_dir, 'xgboost_latest.pkl'))
    
    # Save results
    save_json(results, os.path.join(models_dir, 'xgboost_results.json'))
    save_json(importance, os.path.join(models_dir, 'feature_importance.json'))
    
    logger.info("="*60)
    logger.info("Training complete!")
    logger.info("="*60)


if __name__ == '__main__':
    main()
