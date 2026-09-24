import os

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_FILE = (
    "step12/dataset/expanded_network_dataset.csv"
)

MODEL_DIR = "step14/models"

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "threat_detection_model.pkl"
)


FEATURE_COLUMNS = [

    "packets",
    "bytes",

    "unique_destination_ips",
    "unique_destination_ports",

    "duration",

    "packets_per_sec",
    "bytes_per_sec",

    "tcp_packets",

    "syn_packets",
    "ack_packets",
    "rst_packets",
    "fin_packets",

    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
    "fin_ratio",

    "dns_packets",

    "average_inter_arrival"
]


TARGET_COLUMN = "label"


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset():

    print()
    print("=" * 100)
    print("LOADING TRAINING DATASET")
    print("=" * 100)

    df = pd.read_csv(
        DATASET_FILE
    )

    print()
    print(
        f"Dataset file : {DATASET_FILE}"
    )

    print(
        f"Total records: {len(df)}"
    )

    return df


# ============================================================
# PREPARE DATA
# ============================================================

def prepare_data(df):

    print()
    print("=" * 100)
    print("PREPARING TRAINING DATA")
    print("=" * 100)

    X = df[
        FEATURE_COLUMNS
    ].copy()

    y = df[
        TARGET_COLUMN
    ].copy()

    X = X.replace(
        [float("inf"), float("-inf")],
        0
    )

    X = X.fillna(0)

    print()
    print(
        f"Feature matrix: {X.shape}"
    )

    print(
        f"Target vector : {y.shape}"
    )

    print()

    print("Class distribution:")

    for label, count in (
        y.value_counts().items()
    ):

        print(
            f"  {label:20s}: {count}"
        )

    return X, y


# ============================================================
# TRAIN MODEL
# ============================================================

def train_model(
    X_train,
    y_train
):

    print()
    print("=" * 100)
    print("TRAINING RANDOM FOREST")
    print("=" * 100)

    model = RandomForestClassifier(

        n_estimators=200,

        random_state=42,

        class_weight="balanced",

        n_jobs=-1
    )

    model.fit(
        X_train,
        y_train
    )

    print()
    print(
        "Random Forest training complete."
    )

    return model


# ============================================================
# EVALUATE MODEL
# ============================================================

def evaluate_model(
    model,
    X_test,
    y_test
):

    print()
    print("=" * 100)
    print("MODEL VALIDATION")
    print("=" * 100)

    predictions = model.predict(
        X_test
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print()

    print(
        f"Accuracy: {accuracy:.4f}"
    )

    print()
    print("Classification Report:")
    print()

    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )

    print()
    print("Confusion Matrix:")
    print()

    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )


# ============================================================
# SAVE MODEL
# ============================================================

def save_model(model):

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    joblib.dump(
        model,
        MODEL_FILE
    )

    print()
    print("=" * 100)
    print("MODEL SAVED")
    print("=" * 100)

    print()
    print(
        f"Model file: {MODEL_FILE}"
    )

    print()


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 100)
    print(
        "STEP 14 - PERSISTENT ML MODEL TRAINING"
    )
    print("=" * 100)

    df = load_dataset()

    X, y = prepare_data(
        df
    )

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.25,
            random_state=42,
            stratify=y
        )
    )

    print()
    print("=" * 100)
    print("TRAIN / TEST SPLIT")
    print("=" * 100)

    print()

    print(
        f"Training records: {len(X_train)}"
    )

    print(
        f"Testing records : {len(X_test)}"
    )

    model = train_model(
        X_train,
        y_train
    )

    evaluate_model(
        model,
        X_test,
        y_test
    )

    save_model(
        model
    )

    print()
    print("=" * 100)
    print("STEP 14 TRAINING COMPLETE")
    print("=" * 100)


if __name__ == "__main__":
    main()