"""
offline_evaluator.py
Reusable offline evaluation utility for NIDS model inference validation.

Accepts model predictions and independently established ground-truth labels,
validates class mapping contracts, constructs confusion matrices, and computes
per-class precision, recall, F1, and intrusion-detection operational metrics
(False Alarm Rate / False Positive Rate, Missed Attack Rate / False Negative Rate).
"""

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
import numpy as np
import pandas as pd


@dataclass
class ClassMetrics:
    class_name: str
    class_id: Optional[int]
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    support: int
    precision: float
    recall: float
    specificity: float
    f1_score: float


@dataclass
class BinaryIntrusionMetrics:
    """Metrics aggregated into Binary Intrusion Detection (BENIGN vs ATTACK)."""
    benign_support: int
    attack_support: int
    benign_correct: int
    attack_correct: int
    false_positives: int  # Benign misclassified as Attack (False Alarm)
    false_negatives: int  # Attack misclassified as Benign (Missed Attack)
    false_positive_rate: float  # FP / (FP + TN_attack) == FP / Benign_support
    missed_attack_rate: float   # FN / (FN + TP_attack) == FN / Attack_support
    precision: float
    recall: float
    f1_score: float


@dataclass
class EvaluationReport:
    total_samples: int
    accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    weighted_precision: float
    weighted_recall: float
    weighted_f1: float
    class_names: List[str]
    confusion_matrix: List[List[int]]  # rows: actual, cols: predicted
    per_class_metrics: Dict[str, ClassMetrics]
    binary_intrusion_metrics: Optional[BinaryIntrusionMetrics] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_classification_dataframe(self) -> pd.DataFrame:
        records = []
        for name, m in self.per_class_metrics.items():
            records.append({
                "Class": name,
                "Class_ID": m.class_id,
                "Support": m.support,
                "TP": m.true_positives,
                "FP": m.false_positives,
                "FN": m.false_negatives,
                "TN": m.true_negatives,
                "Precision": round(m.precision, 6),
                "Recall": round(m.recall, 6),
                "Specificity": round(m.specificity, 6),
                "F1_Score": round(m.f1_score, 6),
            })
        return pd.DataFrame(records)

    def to_confusion_matrix_dataframe(self) -> pd.DataFrame:
        return pd.DataFrame(
            self.confusion_matrix,
            index=[f"Actual_{c}" for c in self.class_names],
            columns=[f"Pred_{c}" for c in self.class_names],
        )


class OfflineEvaluator:
    """
    Offline evaluation engine for validating classification accuracy and
    detection rates against independently established ground truth.
    """

    def __init__(
        self,
        label_mapping: Optional[Union[Dict[Any, str], Dict[str, Any]]] = None,
        benign_label: str = "BENIGN",
    ):
        """
        Initializes the evaluator.
        :param label_mapping: Optional mapping between class IDs and string names.
               Can be {0: "BENIGN", 1: "Bot"} or {"0": "BENIGN"} or {"BENIGN": 0}.
        :param benign_label: String label designated as benign baseline.
        """
        self.benign_label = benign_label
        self.id_to_name: Dict[int, str] = {}
        self.name_to_id: Dict[str, int] = {}

        if label_mapping:
            self._load_label_mapping(label_mapping)

    def _load_label_mapping(self, mapping: Union[Dict[Any, str], Dict[str, Any]]) -> None:
        """Normalizes and loads label mapping."""
        for k, v in mapping.items():
            # Check if key is integer or numeric string
            if isinstance(k, int) or (isinstance(k, str) and k.isdigit()):
                c_id = int(k)
                c_name = str(v)
                self.id_to_name[c_id] = c_name
                self.name_to_id[c_name] = c_id
            elif isinstance(v, int) or (isinstance(v, str) and str(v).isdigit()):
                c_name = str(k)
                c_id = int(v)
                self.id_to_name[c_id] = c_name
                self.name_to_id[c_name] = c_id
            else:
                raise ValueError(f"Invalid label mapping pair: ({k}: {v}). Must map integer ID to class name.")

    def _normalize_item(self, item: Any) -> str:
        """Converts an integer ID, string ID, or string label to normalized class name."""
        if isinstance(item, (int, np.integer)):
            if self.id_to_name and int(item) in self.id_to_name:
                return self.id_to_name[int(item)]
            elif self.id_to_name:
                raise ValueError(f"Unsupported class ID: {item}. Allowed IDs: {list(self.id_to_name.keys())}")
            return f"Class_{item}"

        if isinstance(item, str):
            item_s = item.strip()
            if self.id_to_name and item_s.isdigit() and int(item_s) in self.id_to_name:
                return self.id_to_name[int(item_s)]
            if self.name_to_id:
                if item_s in self.name_to_id:
                    return item_s
                raise ValueError(f"Unsupported class name: '{item_s}'. Allowed classes: {list(self.name_to_id.keys())}")
            return item_s

        raise ValueError(f"Unsupported label type: {type(item)} for value {item}")

    def evaluate(
        self,
        y_true: Sequence[Any],
        y_pred: Sequence[Any],
        allowed_classes: Optional[Sequence[str]] = None,
    ) -> EvaluationReport:
        """
        Executes offline evaluation across true labels and predictions.

        :param y_true: Ground-truth labels (class IDs or string names).
        :param y_pred: Predicted labels (class IDs or string names).
        :param allowed_classes: Optional explicit list and ordering of classes.
        :return: EvaluationReport containing full diagnostic tables.
        """
        n_true = len(y_true)
        n_pred = len(y_pred)

        if n_true == 0 or n_pred == 0:
            raise ValueError(f"Input arrays cannot be empty. Received y_true: {n_true}, y_pred: {n_pred}.")

        if n_true != n_pred:
            raise ValueError(f"Mismatched input lengths: y_true has {n_true} samples, y_pred has {n_pred} samples.")

        # Normalize to class names
        norm_true = [self._normalize_item(x) for x in y_true]
        norm_pred = [self._normalize_item(x) for x in y_pred]

        # Determine class list
        if allowed_classes:
            classes = list(allowed_classes)
            # Verify no unknown classes in normalized data
            for val in set(norm_true) | set(norm_pred):
                if val not in classes:
                    raise ValueError(f"Encountered class '{val}' not present in allowed_classes: {classes}")
        elif self.name_to_id:
            # Preserve ordering from label mapping
            classes = [self.id_to_name[i] for i in sorted(self.id_to_name.keys())]
        else:
            # Sort unique classes observed
            classes = sorted(list(set(norm_true) | set(norm_pred)))

        num_classes = len(classes)
        class_to_idx = {c: i for i, c in enumerate(classes)}

        # Build confusion matrix (rows = actual, cols = predicted)
        cm = [[0 for _ in range(num_classes)] for _ in range(num_classes)]
        for t, p in zip(norm_true, norm_pred):
            cm[class_to_idx[t]][class_to_idx[p]] += 1

        total_samples = n_true
        correct_predictions = sum(cm[i][i] for i in range(num_classes))
        accuracy = correct_predictions / total_samples if total_samples > 0 else 0.0

        # Calculate per-class metrics
        per_class: Dict[str, ClassMetrics] = {}
        col_sums = [sum(cm[r][c] for r in range(num_classes)) for c in range(num_classes)]
        row_sums = [sum(cm[r][c] for c in range(num_classes)) for r in range(num_classes)]

        macro_p_sum = 0.0
        macro_r_sum = 0.0
        macro_f1_sum = 0.0

        weighted_p_sum = 0.0
        weighted_r_sum = 0.0
        weighted_f1_sum = 0.0
        total_support = sum(row_sums)

        for i, c_name in enumerate(classes):
            tp = cm[i][i]
            fp = col_sums[i] - tp
            fn = row_sums[i] - tp
            tn = total_samples - (tp + fp + fn)
            support = row_sums[i]

            # Precision = TP / (TP + FP) with zero-division protection
            precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0

            # Recall = TP / (TP + FN) with zero-division protection
            recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0

            # Specificity = TN / (TN + FP) with zero-division protection
            specificity = (tn / (tn + fp)) if (tn + fp) > 0 else 0.0

            # F1 Score = 2 * (P * R) / (P + R)
            if (precision + recall) > 0:
                f1 = 2.0 * (precision * recall) / (precision + recall)
            else:
                f1 = 0.0

            macro_p_sum += precision
            macro_r_sum += recall
            macro_f1_sum += f1

            weighted_p_sum += precision * support
            weighted_r_sum += recall * support
            weighted_f1_sum += f1 * support

            c_id = self.name_to_id.get(c_name)
            per_class[c_name] = ClassMetrics(
                class_name=c_name,
                class_id=c_id,
                true_positives=tp,
                false_positives=fp,
                true_negatives=tn,
                false_negatives=fn,
                support=support,
                precision=precision,
                recall=recall,
                specificity=specificity,
                f1_score=f1,
            )

        macro_p = macro_p_sum / num_classes if num_classes > 0 else 0.0
        macro_r = macro_r_sum / num_classes if num_classes > 0 else 0.0
        macro_f1 = macro_f1_sum / num_classes if num_classes > 0 else 0.0

        weighted_p = (weighted_p_sum / total_support) if total_support > 0 else 0.0
        weighted_r = (weighted_r_sum / total_support) if total_support > 0 else 0.0
        weighted_f1 = (weighted_f1_sum / total_support) if total_support > 0 else 0.0

        # Compute Binary Intrusion Metrics (BENIGN vs ANY_ATTACK) if BENIGN is present
        binary_metrics: Optional[BinaryIntrusionMetrics] = None
        if self.benign_label in classes:
            b_idx = class_to_idx[self.benign_label]
            benign_supp = row_sums[b_idx]
            attack_supp = total_samples - benign_supp

            benign_correct = cm[b_idx][b_idx]
            # False Positive (False Alarm): Actually BENIGN, predicted as ANY Attack
            false_alarms = sum(cm[b_idx][c] for c in range(num_classes) if c != b_idx)

            # Attack Correct (True Positives for Attack): Actually Attack, predicted as ANY Attack
            attack_correct = sum(
                cm[r][c]
                for r in range(num_classes) if r != b_idx
                for c in range(num_classes) if c != b_idx
            )

            # Missed Attack (False Negatives for Attack): Actually Attack, predicted as BENIGN
            missed_attacks = sum(cm[r][b_idx] for r in range(num_classes) if r != b_idx)

            # Operational rates:
            fpr = (false_alarms / benign_supp) if benign_supp > 0 else 0.0
            mar = (missed_attacks / attack_supp) if attack_supp > 0 else 0.0

            # Attack Precision & Recall
            tot_attack_preds = attack_correct + false_alarms
            attack_prec = (attack_correct / tot_attack_preds) if tot_attack_preds > 0 else 0.0
            attack_rec = (attack_correct / attack_supp) if attack_supp > 0 else 0.0
            attack_f1 = (
                (2.0 * attack_prec * attack_rec / (attack_prec + attack_rec))
                if (attack_prec + attack_rec) > 0
                else 0.0
            )

            binary_metrics = BinaryIntrusionMetrics(
                benign_support=benign_supp,
                attack_support=attack_supp,
                benign_correct=benign_correct,
                attack_correct=attack_correct,
                false_positives=false_alarms,
                false_negatives=missed_attacks,
                false_positive_rate=fpr,
                missed_attack_rate=mar,
                precision=attack_prec,
                recall=attack_rec,
                f1_score=attack_f1,
            )

        return EvaluationReport(
            total_samples=total_samples,
            accuracy=accuracy,
            macro_precision=macro_p,
            macro_recall=macro_r,
            macro_f1=macro_f1,
            weighted_precision=weighted_p,
            weighted_recall=weighted_r,
            weighted_f1=weighted_f1,
            class_names=classes,
            confusion_matrix=cm,
            per_class_metrics=per_class,
            binary_intrusion_metrics=binary_metrics,
        )
