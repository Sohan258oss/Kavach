"""
ml/feature_extractor.py — Mirror of monitor/feature_extractor.py.

Re-exports the runtime feature extractor so that ``from ml.feature_extractor
import extract_features`` keeps working for any scripts that import from
the ml package.
"""

# Re-export everything from the canonical module
from monitor.feature_extractor import (      # noqa: F401
    extract_features,
    validate_features,
    FeatureDict,
)