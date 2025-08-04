"""
Reporting and visualization components.

Available modules:
- visualizations: Matplotlib/Seaborn charts
- pdf_report: PDF generation
- email_sender: Email distribution
"""

from .visualizations import (
    plot_connection_heatmap,
    generate_traffic_timeline
)

from .pdf_report import generate_pdf_report

__all__ = [
    'plot_connection_heatmap',
    'generate_traffic_timeline',
    'generate_pdf_report'
]