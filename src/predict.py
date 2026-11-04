"""Predict whether an email is phishing."""
import argparse
import os
import joblib
import pandas as pd

from features import extract_all

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE, "models")


def predict_one(subject, body, sender):
    clf = joblib.load(os.path.join(MODEL_DIR, "model.joblib"))
    tfidf = joblib.load(os.path.join(MODEL_DIR, "tfidf.joblib"))
    feature_names = joblib.load(os.path.join(MODEL_DIR, "feature_names.joblib"))

    f = extract_all(subject, body, sender)
    feat_df = pd.DataFrame([f])
    X_text = tfidf.transform([f"{subject} {body}"])
    X = pd.concat([feat_df.reset_index(drop=True),
                   pd.DataFrame(X_text.toarray(), columns=tfidf.get_feature_names_out())], axis=1)
    # align columns
    for c in feature_names:
        if c not in X.columns:
            X[c] = 0
    X = X[feature_names]
    prob = clf.predict_proba(X)[0][1]
    label = "PHISHING" if prob >= 0.5 else "LEGITIMATE"
    return label, prob


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--subject", default="")
    parser.add_argument("--body", default="")
    parser.add_argument("--sender", default="")
    parser.add_argument("--text", default=None, help="Full email text (subject+body)")
    args = parser.parse_args()

    if args.text:
        subject, body = args.text, args.text
    else:
        subject, body = args.subject, args.body

    label, prob = predict_one(subject, body, args.sender)
    print(f"Prediction: {label} (phishing probability: {prob:.2%})")


if __name__ == "__main__":
    main()