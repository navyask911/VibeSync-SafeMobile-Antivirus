#!/usr/bin/env python3
"""Offline-only training of static Android malware features. NOT for GitHub Actions.
Install locally: pip install tensorflow==2.17.0 scikit-learn numpy
Supply a licensed local CSV (no downloading or uploading): label (0 benign, 1 malware)
and every column in FEATURES below. For CICMalDroid static feature exports, create a
local mapping to the exact feature names/semantics below; missing fields are an
error, never silently set to zero. Dataset access and redistribution permissions
must be reviewed separately. No training dataset is bundled.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path

FEATURES = [
    "perm.INTERNET", "perm.READ_SMS", "perm.RECEIVE_SMS", "perm.SEND_SMS",
    "perm.READ_CONTACTS", "perm.WRITE_CONTACTS", "perm.READ_CALL_LOG",
    "perm.WRITE_CALL_LOG", "perm.READ_PHONE_STATE", "perm.RECORD_AUDIO",
    "perm.CAMERA", "perm.ACCESS_FINE_LOCATION", "perm.ACCESS_COARSE_LOCATION",
    "perm.SYSTEM_ALERT_WINDOW", "perm.REQUEST_INSTALL_PACKAGES",
    "perm.QUERY_ALL_PACKAGES", "perm.READ_EXTERNAL_STORAGE",
    "perm.WRITE_EXTERNAL_STORAGE", "perm.RECEIVE_BOOT_COMPLETED",
    "perm.BIND_ACCESSIBILITY_SERVICE",
    "intent.BOOT_COMPLETED", "intent.SMS_RECEIVED", "intent.PACKAGE_ADDED",
    "intent.DEVICE_ADMIN_ENABLED", "intent.MAIN", "intent.VIEW",
    "api.SmsManager.sendTextMessage", "api.TelephonyManager.getDeviceId",
    "api.Runtime.exec", "api.DexClassLoader", "api.Class.forName",
    "api.AccessibilityService"
]
OUTPUT = Path("app/src/main/assets/malware_model.tflite")
MAX_MODEL_BYTES = 50 * 1024 * 1024

def read_csv(path):
    import numpy as np
    data, labels = [], []
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        missing = sorted(set(FEATURES + ["label"]) - set(reader.fieldnames or []))
        if missing:
            raise ValueError("Missing fields: " + ", ".join(missing))
        for line in reader:
            label = line["label"].strip().lower()
            if label not in ("0", "1", "benign", "malware"):
                raise ValueError("Invalid label")
            labels.append(int(label in ("1", "malware")))
            data.append([float(float(line[name]) > 0) for name in FEATURES])
    return np.asarray(data, dtype=np.float32), np.asarray(labels, dtype=np.int32)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True, type=Path, help="Authorized local Android static-feature export")
    parser.add_argument("--dataset-name", required=True)
    parser.add_argument("--license-note", required=True, help="Legal source and permitted intended use")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    import numpy as np
    import tensorflow as tf
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import roc_auc_score, precision_score, recall_score
    X, y = read_csv(args.csv)
    if len(y) < 100 or set(y) != {0, 1} or min(np.bincount(y)) < 25:
        raise ValueError("Insufficient benign and malware samples")
    X_tr, X_hold, y_tr, y_hold = train_test_split(
        X, y, stratify=y, test_size=0.3, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_hold, y_hold, stratify=y_hold, test_size=0.5, random_state=42
    )
    classifier = LogisticRegression(max_iter=1500, class_weight="balanced", random_state=42)
    classifier.fit(X_tr, y_tr)
    validation_auc = float(roc_auc_score(y_val, classifier.predict_proba(X_val)[:, 1]))
    scores = classifier.predict_proba(X_test)[:, 1]
    predicted = scores > 0.85
    metrics = {
        "held_out_auc": float(roc_auc_score(y_test, scores)),
        "held_out_precision_at_085": float(precision_score(y_test, predicted, zero_division=0)),
        "held_out_recall_at_085": float(recall_score(y_test, predicted, zero_division=0)),
        "validation_auc": validation_auc,
        "test_sample_count": int(len(y_test)),
    }
    # The single sigmoid Dense layer exactly represents logistic regression.
    model = tf.keras.Sequential([tf.keras.Input(shape=(len(FEATURES),)),
                                 tf.keras.layers.Dense(1, activation="sigmoid")])
    model(np.zeros((1, len(FEATURES)), dtype=np.float32))
    model.layers[0].set_weights([classifier.coef_.astype(np.float32).T,
                                classifier.intercept_.astype(np.float32)])
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    output = converter.convert()
    if output[4:8] != b"TFL3" or len(output) >= MAX_MODEL_BYTES:
        raise ValueError("Invalid or oversized TFLite model")
    interpreter = tf.lite.Interpreter(model_content=output, num_threads=1)
    interpreter.allocate_tensors()
    a, b = interpreter.get_input_details()[0], interpreter.get_output_details()[0]
    if list(a["shape"]) != [1, len(FEATURES)] or list(b["shape"]) != [1, 1]:
        raise ValueError("Unexpected input/output tensor shape")
    interpreter.set_tensor(a["index"], np.zeros((1, len(FEATURES)), dtype=np.float32))
    interpreter.invoke()
    if not np.isfinite(interpreter.get_tensor(b["index"])).all():
        raise ValueError("Model output is not finite")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    manifest = {
        "schema_version": 1, "feature_count": len(FEATURES), "features": FEATURES,
        "model_sha256": hashlib.sha256(output).hexdigest(),
        "trained": True, "validated": False, "status": "candidate_unreviewed",
        "dataset": args.dataset_name, "license": args.license_note,
        "samples": int(len(y)), "threshold": 0.85, "metrics": metrics,
        "review_required": "Independent validation, provenance and license review required before enabling."
    }
    args.output.with_suffix(".json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps({"bytes": len(output), "metrics": metrics,
                      "enabled": False}, indent=2))

if __name__ == "__main__":
    main()
