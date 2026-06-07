from modules.ai.dataset_builder import DatasetBuilder
from modules.ai.feature_engineering import FeatureEngineering
from modules.ai.training_pipeline import TrainingPipeline
from modules.ai.model_trainer import ModelTrainer
from modules.ai.model_evaluator import ModelEvaluator
from modules.ai.mitre_predictor import MitrePredictor
from modules.ai.risk_predictor import RiskPredictor
from modules.ai.attack_path_predictor import AttackPathPredictor
from modules.ai.adversary_similarity import AdversarySimilarity
from modules.ai.recommendation_engine import RecommendationEngine
from modules.ai.explainable_ai import ExplainableAI
from modules.ai.model_registry import ModelRegistry

# IMPORTANT: define alias explicitly
AIPipeline = TrainingPipeline

__all__ = [
    "DatasetBuilder",
    "FeatureEngineering",
    "TrainingPipeline",
    "ModelTrainer",
    "ModelEvaluator",
    "MitrePredictor",
    "RiskPredictor",
    "AttackPathPredictor",
    "AdversarySimilarity",
    "RecommendationEngine",
    "ExplainableAI",
    "ModelRegistry",
    "AIPipeline"
]
