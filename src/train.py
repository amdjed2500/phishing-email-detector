"""Train the phishing detector model."""
import os
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

from features import extract_all

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data", "sample_emails.csv")
MODEL_DIR = os.path.join(BASE, "models")
os.makedirs(MODEL_DIR, exist_ok=True)


def build_features(df):
    rows = []
    for _, r in df.iterrows():
        f = extract_all(r["subject"], r["body"], r["sender"])
        rows.append(f)
    feat_df = pd.DataFrame(rows)
    return feat_df


def main():
    df = pd.read_csv(DATA)
    feat_df = build_features(df)
    tfidf = TfidfVectorizer(max_features=200, stop_words="english")
    X_text = tfidf.fit_transform(df["subject"].fillna("") + " " + df["body"].fillna(""))
    X = pd.concat([feat_df.reset_index(drop=True),
                   pd.DataFrame(X_text.toarray(), columns=tfidf.get_feature_names_out())], axis=1)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=200, random_state=42)
    clf.fit(X_train, y_train)

    pred = clf.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, pred))
    print(classification_report(y_test, pred))

    joblib.dump(clf, os.path.join(MODEL_DIR, "model.joblib"))
    joblib.dump(tfidf, os.path.join(MODEL_DIR, "tfidf.joblib"))
    joblib.dump(list(X.columns), os.path.join(MODEL_DIR, "feature_names.joblib"))
    print("Model saved to", MODEL_DIR)


if __name__ == "__main__":
    main()