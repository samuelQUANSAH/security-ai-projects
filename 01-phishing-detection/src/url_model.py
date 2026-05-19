"""
URL-based phishing detection using Random Forest + lexical features.
Complements the BERT text model with host-level signal.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)
import joblib
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class URLPhishingDetector:
    """
    Random Forest classifier on URL lexical features.

    Why Random Forest?
    - Handles mixed feature types (categorical + continuous) without scaling
    - Feature importance provides explainability (critical for security)
    - Fast inference (<1ms per URL) — ideal for real-time email gateways
    - Robust to overfitting with default hyperparameters
    """

    def __init__(
        self,
        n_estimators: int = 200,
        max_depth: int = 20,
        min_samples_split: int = 5,
        class_weight: str = "balanced",
        random_state: int = 42,
    ):
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            class_weight=class_weight,
            random_state=random_state,
            n_jobs=-1,  # Use all CPU cores
        )
        self.is_trained = False
        self.feature_names = None

    def train(
        self,
        X: pd.DataFrame,
        y: pd.Series,
        test_size: float = 0.2,
        cv_folds: int = 5,
    ) -> dict:
        """
        Train URL classifier with cross-validation.

        Args:
            X: Feature DataFrame (from URLFeatureExtractor)
            y: Labels (1=phishing, 0=legitimate)
            test_size: Hold-out test split
            cv_folds: Stratified CV folds

        Returns:
            Dict with train/test metrics and CV scores
        """
        self.feature_names = X.columns.tolist()

        # Train/test split (stratified)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, stratify=y, random_state=42
        )

        # Cross-validation on training set
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        cv_scores = cross_val_score(self.model, X_train, y_train, cv=cv, scoring="f1")

        logger.info(f"CV F1 scores: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")

        # Train final model on full training set
        self.model.fit(X_train, y_train)
        self.is_trained = True

        # Evaluate on hold-out test
        y_pred = self.model.predict(X_test)
        y_proba = self.model.predict_proba(X_test)[:, 1]

        metrics = {
            "cv_f1_mean": cv_scores.mean(),
            "cv_f1_std": cv_scores.std(),
            "test_accuracy": accuracy_score(y_test, y_pred),
            "test_precision": precision_score(y_test, y_pred),
            "test_recall": recall_score(y_test, y_pred),
            "test_f1": f1_score(y_test, y_pred),
            "test_auc_roc": roc_auc_score(y_test, y_proba),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "feature_importance": self.get_feature_importance(),
        }

        logger.info(f"Test F1: {metrics['test_f1']:.3f} | AUC-ROC: {metrics['test_auc_roc']:.3f}")
        logger.info("\n" + classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

        return metrics

    def predict(self, X: pd.DataFrame) -> dict:
        """
        Predict phishing probability for new URLs.
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before prediction")

        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)[:, 1]

        return {
            "predictions": predictions,
            "probabilities": probabilities,
            "labels": ["phishing" if p == 1 else "legitimate" for p in predictions],
        }

    def get_feature_importance(self) -> dict:
        """Return feature importance sorted by contribution."""
        if not self.is_trained:
            raise RuntimeError("Model not trained")

        importance = self.model.feature_importances_
        return dict(
            sorted(
                zip(self.feature_names, importance),
                key=lambda x: x[1],
                reverse=True,
            )
        )

    def save(self, path: str):
        """Serialize model to disk."""
        joblib.dump({
            "model": self.model,
            "feature_names": self.feature_names,
            "is_trained": self.is_trained,
        }, path)
        logger.info(f"Model saved to {path}")

    @classmethod
    def load(cls, path: str):
        """Load model from disk."""
        data = joblib.load(path)
        detector = cls()
        detector.model = data["model"]
        detector.feature_names = data["feature_names"]
        detector.is_trained = data["is_trained"]
        logger.info(f"Model loaded from {path}")
        return detector


if __name__ == "__main__":
    # Quick test with synthetic features
    np.random.seed(42)
    n_samples = 1000

    synthetic_data = pd.DataFrame({
        'url_length': np.random.randint(10, 200, n_samples),
        'hostname_length': np.random.randint(5, 50, n_samples),
        'path_length': np.random.randint(0, 100, n_samples),
        'n_dots': np.random.randint(1, 5, n_samples),
        'n_hyphens': np.random.randint(0, 10, n_samples),
        'n_at': np.random.randint(0, 2, n_samples),
        'n_question_marks': np.random.randint(0, 3, n_samples),
        'n_and': np.random.randint(0, 3, n_samples),
        'n_equal': np.random.randint(0, 5, n_samples),
        'n_underscores': np.random.randint(0, 5, n_samples),
        'n_slashes': np.random.randint(1, 10, n_samples),
        'n_digits': np.random.randint(0, 20, n_samples),
        'has_ip_address': np.random.randint(0, 2, n_samples),
        'has_https': np.random.randint(0, 2, n_samples),
        'tld_length': np.random.randint(2, 6, n_samples),
        'n_subdomains': np.random.randint(0, 4, n_samples),
        'has_suspicious_tld': np.random.randint(0, 2, n_samples),
        'has_shortening_service': np.random.randint(0, 2, n_samples),
    })

    # Synthetic labels: suspicious TLD and shortening service strongly correlate with phishing
    labels = (
        (synthetic_data['has_suspicious_tld'] == 1) |
        (synthetic_data['has_shortening_service'] == 1) |
        (synthetic_data['has_ip_address'] == 1)
    ).astype(int)

    detector = URLPhishingDetector(n_estimators=100)
    metrics = detector.train(synthetic_data, labels)

    print(f"\nTop 5 important features:")
    for feat, imp in list(metrics['feature_importance'].items())[:5]:
        print(f"  {feat}: {imp:.3f}")
