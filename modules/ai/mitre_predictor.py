"""
ai/mitre_predictor.py
----------------------
Wraps the trained classifier for single-sample MITRE tactic prediction.
"""
import pickle, os

class MitrePredictor:

    def __init__(self, model_path: str = "models/mitre_classifier.pkl"):
        self._bundle = None
        if os.path.exists(model_path):
            with open(model_path, "rb") as f:
                self._bundle = pickle.load(f)

    def predict(self, context: dict) -> dict | None:
        if not self._bundle:
            return None
        from modules.ai.feature_engineering import FeatureEngineering
        text  = FeatureEngineering().transform_one(context)
        X     = self._bundle["vectorizer"].transform([text])
        model = self._bundle["model"]
        idx   = model.predict(X)[0]
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X)[0].max()
        elif hasattr(model, "decision_function"):
            import numpy as np
            scores = model.decision_function(X)[0]
            scores = np.exp(scores - scores.max())
            proba  = float(scores.max() / scores.sum())
        else:
            proba = 0.7
        label = self._bundle["label_encoder"].inverse_transform([idx])[0]
        return {"tactic": label, "confidence": round(float(proba), 3), "source": "ml"}
