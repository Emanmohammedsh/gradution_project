"""
ml_classifier.py — Layer 3 of the Hybrid MITRE Engine
-------------------------------------------------------
TF-IDF + Random Forest classifier for MITRE tactic prediction.

Predicts the most likely ATT&CK tactic from:
  - exploit name, service, CVE, port, payload type, post-exploit commands

Confidence: 0.50 – 0.70 (lowest in the stack — used as fallback enrichment)

Training: run train_mitre_model.py to generate models/mitre_classifier.pkl
"""

import os
import re
import pickle
from pathlib import Path


class MitreMLClassifier:

    def __init__(self):
        self.ready = False
        model_path = Path("models/mitre_classifier.pkl")

        if model_path.exists():
            try:
                with open(model_path, "rb") as f:
                    data = pickle.load(f)
                self.model          = data["model"]
                self.vectorizer     = data["vectorizer"]
                self.label_encoder  = data["label_encoder"]
                self.ready          = True
                print("  [MitreMLClassifier] Model loaded.")
            except Exception as e:
                print(f"  [MitreMLClassifier] Failed to load model: {e}")
        else:
            print("  [MitreMLClassifier] No model found — layer 3 disabled.")
            print("  [MitreMLClassifier] Run: python train_mitre_model.py")

    def _build_text(self, context: dict) -> str:
        """Combine all context fields into one text string for TF-IDF."""
        parts = [
            context.get("exploit", ""),
            context.get("service", ""),
            context.get("cve", ""),
            str(context.get("port", "")),
            context.get("payload_type", ""),
            context.get("edb_title", ""),
            context.get("post_commands", ""),
        ]
        # Normalize: lower, replace slashes with spaces
        text = " ".join(p for p in parts if p)
        return re.sub(r'[/_\-]', ' ', text.lower())

    def predict(self, context: dict) -> dict | None:
        if not self.ready:
            return None

        text = self._build_text(context)
        if not text.strip():
            return None

        try:
            vec       = self.vectorizer.transform([text])
            pred_idx  = self.model.predict(vec)[0]
            proba_arr = self.model.predict_proba(vec)[0]
            confidence = float(proba_arr.max())
            tactic     = self.label_encoder.inverse_transform([pred_idx])[0]

            # Retrieve top 2 tactics with their probabilities
            top2_idx = proba_arr.argsort()[-2:][::-1]
            top2 = [
                {
                    "tactic":     self.label_encoder.inverse_transform([i])[0],
                    "confidence": round(float(proba_arr[i]), 2)
                }
                for i in top2_idx
            ]

            return {
                "tactic":      tactic,
                "confidence":  round(confidence, 2),
                "top_tactics": top2,
                "source":      "ml",
                "techniques":  []   # Techniques filled by chain builder from STIX
            }
        except Exception as e:
            print(f"  [MitreMLClassifier] Prediction error: {e}")
            return None
