import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    confusion_matrix
)


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_FILE = (
    "step12/dataset/expanded_network_dataset.csv"
)


# These are the behavioral features that the ML model uses.
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
    print("=" * 90)
    print("LOADING DATASET")
    print("=" * 90)

    df = pd.read_csv(DATASET_FILE)

    print()
    print(f"Dataset file : {DATASET_FILE}")
    print(f"Total records: {len(df)}")
    print()

    return df


# ============================================================
# DATASET INFORMATION
# ============================================================

def show_dataset_information(df):

    print("=" * 90)
    print("DATASET INFORMATION")
    print("=" * 90)

    print()

    print("Feature columns:")
    print()

    for column in FEATURE_COLUMNS:
        print(f"  - {column}")

    print()

    print("Class distribution:")
    print()

    class_counts = df[TARGET_COLUMN].value_counts()

    for label, count in class_counts.items():

        print(
            f"  {label:20s}: {count}"
        )

    print()


# ============================================================
# PREPARE DATA
# ============================================================

def prepare_data(df):

    print("=" * 90)
    print("PREPARING DATA")
    print("=" * 90)

    X = df[FEATURE_COLUMNS].copy()

    y = df[TARGET_COLUMN].copy()

    # Replace invalid numerical values.
    X = X.replace(
        [float("inf"), float("-inf")],
        0
    )

    X = X.fillna(0)

    print()
    print(f"X shape: {X.shape}")
    print(f"y shape: {y.shape}")

    return X, y


# ============================================================
# TRAIN MODEL
# ============================================================

def train_model(X_train, y_train):

    print()
    print("=" * 90)
    print("TRAINING RANDOM FOREST")
    print("=" * 90)

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(
        X_train,
        y_train
    )

    print()
    print("Random Forest training complete.")

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
    print("=" * 90)
    print("MODEL EVALUATION")
    print("=" * 90)

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
# FEATURE IMPORTANCE
# ============================================================

def show_feature_importance(model):

    print()
    print("=" * 90)
    print("FEATURE IMPORTANCE")
    print("=" * 90)

    importances = model.feature_importances_

    feature_importance = sorted(
        zip(
            FEATURE_COLUMNS,
            importances
        ),
        key=lambda x: x[1],
        reverse=True
    )

    print()

    for feature, importance in feature_importance:

        print(
            f"{feature:30s} : "
            f"{importance:.4f}"
        )


# ============================================================
# SAMPLE PREDICTION
# ============================================================

def show_sample_predictions(
    model,
    X_test,
    y_test
):

    print()
    print("=" * 90)
    print("SAMPLE PREDICTIONS")
    print("=" * 90)

    predictions = model.predict(
        X_test
    )

    probabilities = model.predict_proba(
        X_test
    )

    classes = model.classes_

    print()

    for index in range(
        min(10, len(X_test))
    ):

        actual = y_test.iloc[index]

        predicted = predictions[index]

        confidence = max(
            probabilities[index]
        )

        print(
            f"Sample #{index + 1}"
        )

        print(
            f"  Actual     : {actual}"
        )

        print(
            f"  Predicted  : {predicted}"
        )

        print(
            f"  Confidence : {confidence:.4f}"
        )

        print()


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 90)
    print("STEP 11 - MACHINE LEARNING THREAT DETECTOR")
    print("=" * 90)

    df = load_dataset()

    show_dataset_information(
        df
    )

    X, y = prepare_data(
        df
    )

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # Our current dataset is extremely imbalanced and several
    # classes contain only one record.
    #
    # Therefore, a stratified train/test split cannot reliably
    # be performed yet.
    #
    # We first demonstrate the model pipeline using a simple
    # split. A proper balanced dataset will be created later.
    # --------------------------------------------------------

    if len(df) < 20:

        print()
        print(
            "ERROR: Dataset is too small for ML training."
        )

        return

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42
    )

    print()
    print("=" * 90)
    print("TRAIN / TEST SPLIT")
    print("=" * 90)

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

    show_feature_importance(
        model
    )

    show_sample_predictions(
        model,
        X_test,
        y_test
    )

    print()
    print("=" * 90)
    print("STEP 11 COMPLETE")
    print("=" * 90)


if __name__ == "__main__":
    main()