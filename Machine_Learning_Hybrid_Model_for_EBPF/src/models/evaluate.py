"""
Model Evaluation and Comparison

This script:
1. Loads trained models (XGBoost and LSTM)
2. Evaluates them on the test set
3. Compares their performance
4. Generates comprehensive evaluation reports
"""

import os
import sys
import argparse
import numpy as np
from pathlib import Path
from typing import Dict, List, Any
import pickle

import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_curve,
    auc,
    precision_recall_curve,
    average_precision_score
)

# Add project root
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.utils.helpers import (
    setup_logging, 
    load_config, 
    load_json,
    save_json,
    ensure_dir
)


def plot_comparison_roc(
    models_results: Dict[str, Dict],
    output_path: str
):
    """Plot ROC curves for all models."""
    plt.figure(figsize=(10, 8))
    
    colors = ['blue', 'red', 'green', 'orange']
    
    for i, (model_name, results) in enumerate(models_results.items()):
        if 'fpr' in results and 'tpr' in results:
            fpr = results['fpr']
            tpr = results['tpr']
            roc_auc = results.get('roc_auc', auc(fpr, tpr))
            
            plt.plot(
                fpr, tpr, 
                color=colors[i % len(colors)],
                linewidth=2,
                label=f'{model_name} (AUC = {roc_auc:.3f})'
            )
    
    plt.plot([0, 1], [0, 1], 'k--', linewidth=1)
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title('ROC Curve Comparison', fontsize=14)
    plt.legend(loc='lower right', fontsize=11)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()


def plot_comparison_pr(
    models_results: Dict[str, Dict],
    output_path: str
):
    """Plot Precision-Recall curves for all models."""
    plt.figure(figsize=(10, 8))
    
    colors = ['blue', 'red', 'green', 'orange']
    
    for i, (model_name, results) in enumerate(models_results.items()):
        if 'precision_curve' in results and 'recall_curve' in results:
            precision = results['precision_curve']
            recall = results['recall_curve']
            ap = results.get('average_precision', 0)
            
            plt.plot(
                recall, precision,
                color=colors[i % len(colors)],
                linewidth=2,
                label=f'{model_name} (AP = {ap:.3f})'
            )
    
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Recall', fontsize=12)
    plt.ylabel('Precision', fontsize=12)
    plt.title('Precision-Recall Curve Comparison', fontsize=14)
    plt.legend(loc='lower left', fontsize=11)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()


def plot_metrics_comparison(
    models_results: Dict[str, Dict],
    output_path: str
):
    """Bar chart comparing key metrics across models."""
    metrics = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
    model_names = list(models_results.keys())
    
    x = np.arange(len(metrics))
    width = 0.8 / len(model_names)
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12']
    
    for i, model_name in enumerate(model_names):
        values = [models_results[model_name].get(m, 0) for m in metrics]
        offset = (i - len(model_names)/2 + 0.5) * width
        bars = ax.bar(x + offset, values, width, 
                      label=model_name, color=colors[i % len(colors)])
        
        # Add value labels
        for bar, val in zip(bars, values):
            ax.annotate(f'{val:.3f}',
                       xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom', fontsize=9)
    
    ax.set_ylabel('Score', fontsize=12)
    ax.set_title('Model Performance Comparison', fontsize=14)
    ax.set_xticks(x)
    ax.set_xticklabels([m.replace('_', ' ').title() for m in metrics])
    ax.legend()
    ax.set_ylim(0, 1.15)
    ax.grid(True, alpha=0.3, axis='y')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()


def generate_report(
    models_results: Dict[str, Dict],
    output_dir: str
) -> str:
    """Generate a text report comparing models."""
    report_lines = [
        "=" * 70,
        "eBPF MALWARE DETECTION - MODEL EVALUATION REPORT",
        "=" * 70,
        "",
    ]
    
    # Summary table
    report_lines.append("PERFORMANCE SUMMARY")
    report_lines.append("-" * 70)
    report_lines.append(f"{'Model':<20} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1':<12} {'ROC-AUC':<12}")
    report_lines.append("-" * 70)
    
    for model_name, results in models_results.items():
        report_lines.append(
            f"{model_name:<20} "
            f"{results.get('accuracy', 0):<12.4f} "
            f"{results.get('precision', 0):<12.4f} "
            f"{results.get('recall', 0):<12.4f} "
            f"{results.get('f1', 0):<12.4f} "
            f"{results.get('roc_auc', 0):<12.4f}"
        )
    
    report_lines.append("-" * 70)
    report_lines.append("")
    
    # Detailed results for each model
    for model_name, results in models_results.items():
        report_lines.append(f"\n{model_name.upper()} DETAILS")
        report_lines.append("-" * 40)
        
        if 'confusion_matrix' in results:
            cm = results['confusion_matrix']
            if isinstance(cm, list):
                cm = np.array(cm)
            report_lines.append("Confusion Matrix:")
            report_lines.append(f"  True Negatives:  {cm[0,0]}")
            report_lines.append(f"  False Positives: {cm[0,1]}")
            report_lines.append(f"  False Negatives: {cm[1,0]}")
            report_lines.append(f"  True Positives:  {cm[1,1]}")
        
        report_lines.append("")
    
    # Recommendations
    report_lines.append("\nRECOMMENDATIONS")
    report_lines.append("-" * 40)
    
    # Find best model
    best_model = max(models_results.keys(), 
                     key=lambda x: models_results[x].get('f1', 0))
    best_f1 = models_results[best_model].get('f1', 0)
    
    report_lines.append(f"Best performing model: {best_model} (F1 = {best_f1:.4f})")
    
    # Check for high recall (important for malware detection)
    for model_name, results in models_results.items():
        recall = results.get('recall', 0)
        if recall < 0.9:
            report_lines.append(
                f"Warning: {model_name} has low recall ({recall:.2%}). "
                "May miss malicious packages."
            )
    
    report_lines.append("")
    report_lines.append("=" * 70)
    
    report = "\n".join(report_lines)
    
    # Save report
    report_path = os.path.join(output_dir, 'evaluation_report.txt')
    with open(report_path, 'w') as f:
        f.write(report)
    
    return report


def main():
    parser = argparse.ArgumentParser(description='Evaluate and compare models')
    parser.add_argument('--config', type=str, default='configs/config.yaml',
                        help='Path to config file')
    args = parser.parse_args()
    
    # Setup
    logger = setup_logging(name='evaluate')
    config = load_config(args.config)
    
    models_dir = 'trained_models'
    output_dir = os.path.join(models_dir, 'evaluation')
    ensure_dir(output_dir)
    
    logger.info("="*60)
    logger.info("Model Evaluation")
    logger.info("="*60)
    
    models_results = {}
    
    # Load XGBoost results
    xgb_results_path = os.path.join(models_dir, 'xgboost_results.json')
    if os.path.exists(xgb_results_path):
        models_results['XGBoost'] = load_json(xgb_results_path)
        logger.info("Loaded XGBoost results")
    
    # Load LSTM results
    lstm_results_path = os.path.join(models_dir, 'lstm_results.json')
    if os.path.exists(lstm_results_path):
        models_results['BiLSTM'] = load_json(lstm_results_path)
        logger.info("Loaded BiLSTM results")
    
    if not models_results:
        logger.error("No model results found. Please train models first.")
        return
    
    # Generate comparison plots
    logger.info("Generating comparison plots...")
    
    plot_metrics_comparison(
        models_results,
        os.path.join(output_dir, 'metrics_comparison.png')
    )
    
    # Generate report
    report = generate_report(models_results, output_dir)
    print(report)
    
    # Save combined results
    save_json(models_results, os.path.join(output_dir, 'all_results.json'))
    
    logger.info("="*60)
    logger.info("Evaluation complete!")
    logger.info(f"Results saved to {output_dir}")
    logger.info("="*60)


if __name__ == '__main__':
    main()
