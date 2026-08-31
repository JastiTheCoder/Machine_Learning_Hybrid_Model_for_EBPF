"""
Visualization Generator for Phase 3 Report
===========================================
Creates publication-ready figures for the ML analysis results.

Created for Phase 3 Progress Report
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

OUTPUT_DIR = Path(__file__).parent / "outputs"
FIGURES_DIR = Path(__file__).parent / "figures"

# Style settings
plt.style.use('seaborn-v0_8-whitegrid')
COLORS = {
    'primary': '#2563eb',    # Blue
    'secondary': '#16a34a',  # Green
    'danger': '#dc2626',     # Red
    'neutral': '#6b7280',    # Gray
}

# ============================================================================
# FIGURE 1: Feature Importance Bar Chart
# ============================================================================

def create_feature_importance_chart():
    """Create a horizontal bar chart of feature importances."""
    
    # Load data
    rf_imp = pd.read_csv(OUTPUT_DIR / "rf_feature_importances.csv")
    
    # Take top 15 features
    top_features = rf_imp.head(15).copy()
    top_features = top_features.sort_values("importance", ascending=True)
    
    # Create figure
    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Create horizontal bar chart
    colors = [COLORS['primary'] if 'tcp' in feat else COLORS['neutral'] 
              for feat in top_features['feature']]
    
    bars = ax.barh(top_features['feature'], top_features['importance'], color=colors)
    
    # Add value labels
    for bar, val in zip(bars, top_features['importance']):
        ax.text(val + 0.005, bar.get_y() + bar.get_height()/2, 
                f'{val:.3f}', va='center', fontsize=10)
    
    # Clean up feature names for display
    ax.set_yticklabels([f.replace('_', ' ').title() for f in top_features['feature']])
    
    ax.set_xlabel('Feature Importance (Random Forest)', fontsize=12)
    ax.set_title('Top 15 Most Important Features for Malicious Package Detection', 
                 fontsize=14, fontweight='bold')
    
    # Add legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=COLORS['primary'], label='TCP/Network Features'),
        Patch(facecolor=COLORS['neutral'], label='Other Features')
    ]
    ax.legend(handles=legend_elements, loc='lower right')
    
    plt.tight_layout()
    
    # Save
    fig.savefig(FIGURES_DIR / "feature_importance.png", dpi=150, bbox_inches='tight')
    print(f"Saved: {FIGURES_DIR / 'feature_importance.png'}")
    
    plt.close()

# ============================================================================
# FIGURE 2: Feature Discriminability Heatmap
# ============================================================================

def create_discriminability_heatmap():
    """Create a heatmap showing feature discriminability scores."""
    
    # Load data
    disc = pd.read_csv(OUTPUT_DIR / "feature_discriminability.csv")
    
    # Take top 12 features
    top_disc = disc.head(12).copy()
    
    # Create data for heatmap
    data = top_disc[['benign_mean', 'malicious_mean']].values.T
    
    # Normalize each feature to 0-1 for better visualization
    data_norm = (data - data.min(axis=0)) / (data.max(axis=0) - data.min(axis=0) + 1e-10)
    
    fig, ax = plt.subplots(figsize=(14, 5))
    
    # Create heatmap
    im = ax.imshow(data_norm, cmap='RdYlGn', aspect='auto', vmin=0, vmax=1)
    
    # Set labels
    ax.set_xticks(range(len(top_disc)))
    ax.set_xticklabels([f.replace('_', '\n') for f in top_disc['feature']], 
                       rotation=45, ha='right', fontsize=9)
    ax.set_yticks([0, 1])
    ax.set_yticklabels(['Benign\n(avg)', 'Malicious\n(avg)'], fontsize=11)
    
    # Add values in cells
    for i in range(2):
        for j in range(len(top_disc)):
            val = data[i, j]
            text_color = 'white' if data_norm[i, j] < 0.3 or data_norm[i, j] > 0.7 else 'black'
            ax.text(j, i, f'{val:.1f}', ha='center', va='center', 
                   fontsize=9, color=text_color)
    
    ax.set_title('Feature Values: Benign vs Malicious Packages', 
                 fontsize=14, fontweight='bold', pad=20)
    
    # Colorbar
    cbar = plt.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label('Normalized Value', fontsize=10)
    
    plt.tight_layout()
    
    fig.savefig(FIGURES_DIR / "feature_heatmap.png", dpi=150, bbox_inches='tight')
    print(f"Saved: {FIGURES_DIR / 'feature_heatmap.png'}")
    
    plt.close()

# ============================================================================
# FIGURE 3: Dataset Composition
# ============================================================================

def create_dataset_composition():
    """Create a pie chart showing dataset composition."""
    
    # Load data
    sessions = pd.read_csv(OUTPUT_DIR / "sessions_flattened.csv")
    
    # Count by package type
    pkg_counts = sessions['package_name'].value_counts()
    label_counts = sessions['label'].value_counts()
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    # Pie chart 1: By label
    colors1 = [COLORS['secondary'], COLORS['danger']]
    ax1.pie(label_counts.values, labels=label_counts.index, autopct='%1.0f%%',
            colors=colors1, explode=[0, 0.1], shadow=True, startangle=90)
    ax1.set_title('Dataset by Label', fontsize=12, fontweight='bold')
    
    # Pie chart 2: By package
    colors2 = plt.cm.Pastel1(np.linspace(0, 1, len(pkg_counts)))
    wedges, texts, autotexts = ax2.pie(pkg_counts.values, autopct='%1.0f%%',
                                        colors=colors2, pctdistance=0.8)
    ax2.legend(wedges, [p[:20] + '...' if len(p) > 20 else p for p in pkg_counts.index],
               title="Packages", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
    ax2.set_title('Dataset by Package', fontsize=12, fontweight='bold')
    
    plt.suptitle('Current Dataset Composition (10 Sessions)', 
                 fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    
    fig.savefig(FIGURES_DIR / "dataset_composition.png", dpi=150, bbox_inches='tight')
    print(f"Saved: {FIGURES_DIR / 'dataset_composition.png'}")
    
    plt.close()

# ============================================================================
# FIGURE 4: TCP Activity Comparison
# ============================================================================

def create_tcp_comparison():
    """Create bar chart comparing TCP activity between benign and malicious."""
    
    # Load data
    sessions = pd.read_csv(OUTPUT_DIR / "sessions_flattened.csv")
    
    tcp_features = ['tcp_state_transitions', 'tcp_remote_ips', 
                    'tcp_remote_ports', 'tcp_local_ports']
    
    # Calculate means
    benign = sessions[sessions['label'] == 'benign'][tcp_features].mean()
    malicious = sessions[sessions['label'] == 'malicious'][tcp_features].mean()
    
    # Create grouped bar chart
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = np.arange(len(tcp_features))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, benign.values, width, label='Benign', 
                   color=COLORS['secondary'], alpha=0.8)
    bars2 = ax.bar(x + width/2, malicious.values, width, label='Malicious', 
                   color=COLORS['danger'], alpha=0.8)
    
    # Add value labels
    for bar in bars1:
        height = bar.get_height()
        ax.annotate(f'{height:.1f}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=10)
    
    for bar in bars2:
        height = bar.get_height()
        ax.annotate(f'{height:.1f}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=10)
    
    ax.set_xlabel('TCP Feature', fontsize=12)
    ax.set_ylabel('Average Value', fontsize=12)
    ax.set_title('TCP Network Activity: Benign vs Malicious Packages', 
                 fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels([f.replace('tcp_', '').replace('_', '\n').title() 
                        for f in tcp_features])
    ax.legend()
    
    plt.tight_layout()
    
    fig.savefig(FIGURES_DIR / "tcp_comparison.png", dpi=150, bbox_inches='tight')
    print(f"Saved: {FIGURES_DIR / 'tcp_comparison.png'}")
    
    plt.close()

# ============================================================================
# FIGURE 5: Data Quality Issues
# ============================================================================

def create_data_quality_chart():
    """Create a visual representation of data quality issues found."""
    
    # Data quality findings
    issues = {
        'write_processes = 0\n(C1 Bug)': 100,  # 100% of samples affected
        'Zero-variance\nfeatures': 15,  # 15 features
        'Malicious\nsamples': 1,  # Only 1 sample
    }
    
    targets = {
        'write_processes = 0\n(C1 Bug)': 0,  # Should be 0% affected
        'Zero-variance\nfeatures': 0,  # Should have variance
        'Malicious\nsamples': 20,  # Want at least 20
    }
    
    fig, ax = plt.subplots(figsize=(10, 5))
    
    x = np.arange(len(issues))
    width = 0.35
    
    current = ax.bar(x - width/2, list(issues.values()), width, 
                     label='Current State', color=COLORS['danger'], alpha=0.8)
    target = ax.bar(x + width/2, list(targets.values()), width, 
                    label='Target State', color=COLORS['secondary'], alpha=0.8)
    
    ax.set_ylabel('Count / Percentage')
    ax.set_title('Data Quality Issues Identified', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(list(issues.keys()))
    ax.legend()
    
    # Add annotations
    ax.annotate('Bug in eBPF monitor\n(Aniruddha fixing)', 
                xy=(-0.17, 100), xytext=(-0.5, 120),
                arrowprops=dict(arrowstyle='->', color='black'),
                fontsize=9)
    
    plt.tight_layout()
    
    fig.savefig(FIGURES_DIR / "data_quality.png", dpi=150, bbox_inches='tight')
    print(f"Saved: {FIGURES_DIR / 'data_quality.png'}")
    
    plt.close()

# ============================================================================
# MAIN
# ============================================================================

def main():
    """Generate all figures."""
    
    # Create figures directory
    FIGURES_DIR.mkdir(exist_ok=True)
    
    print("Generating figures for Phase 3 report...")
    print("=" * 50)
    
    print("\n1. Feature Importance Chart...")
    create_feature_importance_chart()
    
    print("\n2. Feature Discriminability Heatmap...")
    create_discriminability_heatmap()
    
    print("\n3. Dataset Composition...")
    create_dataset_composition()
    
    print("\n4. TCP Activity Comparison...")
    create_tcp_comparison()
    
    print("\n5. Data Quality Issues...")
    create_data_quality_chart()
    
    print("\n" + "=" * 50)
    print(f"All figures saved to: {FIGURES_DIR}")
    print("\nFigures ready for report:")
    for fig_file in sorted(FIGURES_DIR.glob("*.png")):
        print(f"  - {fig_file.name}")

if __name__ == "__main__":
    main()
