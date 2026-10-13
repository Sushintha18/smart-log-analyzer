
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from fastapi import FastAPI
from pydantic import BaseModel
from collections import Counter
import pandas as pd
from sklearn.ensemble import IsolationForest

app = FastAPI(title="Smart Log Analyzer API")


class LogEntry(BaseModel):
    user: str
    event: str
    ip_address: str


class LogRequest(BaseModel):
    logs: list[LogEntry]


def prepare_data(logs):
    df = pd.DataFrame([log.model_dump() for log in logs])

    # ETL: clean the log data
    for column in ["user", "event", "ip_address"]:
        df[column] = df[column].fillna("").astype(str).str.strip()

    df = df[
        (df["user"] != "") &
        (df["event"] != "") &
        (df["ip_address"] != "")
    ]

    df["failed_login"] = (
        df["event"].str.contains("login failed", case=False)
    )

    return df


@app.get("/")
def home():
    return {
        "message": "Smart Log Analyzer API is running",
        "module": "Cloud Engineering"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/analyze")
def analyze_logs(request: LogRequest):
    df = prepare_data(request.logs)

    failed = df[df["failed_login"]]
    counts = Counter(failed["ip_address"])

    suspicious_ips = [
        ip for ip, count in counts.items() if count >= 3
    ]

    return {
        "total_events": int(len(df)),
        "failed_logins": int(len(failed)),
        "suspicious_ips": suspicious_ips
    }


@app.post("/analytics")
def analytics(request: LogRequest):
    df = prepare_data(request.logs)

    event_counts = {
        str(event): int(count)
        for event, count in df["event"].value_counts().items()
    }

    # Aggregate data by IP address
    ip_stats = (
        df.groupby("ip_address")
        .agg(
            total_events=("event", "size"),
            failed_logins=("failed_login", "sum")
        )
        .reset_index()
    )

    ip_stats["total_events"] = ip_stats["total_events"].astype(int)
    ip_stats["failed_logins"] = ip_stats["failed_logins"].astype(int)

    # ML anomaly detection requires at least 5 distinct IPs
    if len(ip_stats) >= 5:
        model = IsolationForest(
            contamination="auto",
            random_state=42
        )

        features = ip_stats[["total_events", "failed_logins"]]
        predictions = model.fit_predict(features)

        ip_stats["ml_result"] = [
            "Anomaly" if result == -1 else "Normal"
            for result in predictions
        ]

        ml_message = "Isolation Forest analysis completed."
    else:
        ip_stats["ml_result"] = "Not evaluated"
        ml_message = (
            "Provide logs from at least 5 distinct IP addresses "
            "for ML anomaly detection."
        )

    return {
        "cleaned_rows": int(len(df)),
        "event_counts": event_counts,
        "ip_analysis": ip_stats.to_dict(orient="records"),
        "ml_message": ml_message
    }

from pydantic import BaseModel

class QuestionRequest(BaseModel):
    question: str


# Small security knowledge base
security_docs = [
    {
        "topic": "Failed Login",
        "text": "Repeated failed logins may indicate password guessing. "
                "Review authentication logs, apply rate limiting, "
                "and consider multi-factor authentication."
    },
    {
        "topic": "Unauthorized Access",
        "text": "Unauthorized access may indicate weak access controls. "
                "Review user permissions and restrict access using "
                "the principle of least privilege."
    },
    {
        "topic": "AWS Security",
        "text": "AWS IAM manages permissions. CloudTrail records "
                "account activity, while CloudWatch monitors logs "
                "and operational events."
    },
    {
        "topic": "Encryption",
        "text": "Encryption protects sensitive information by making "
                "it unreadable without the appropriate key. "
                "Protect encryption keys and restrict access."
    },
    {
        "topic": "Log Analysis",
        "text": "Security logs record events such as successful logins, "
                "failed logins, and unauthorized access. Analyze "
                "patterns to identify suspicious activity."
    }
]


@app.post("/ask")
def ask_security_question(request: QuestionRequest):
    documents = [doc["text"] for doc in security_docs]

    # Convert documents and question into numerical vectors
    vectorizer = TfidfVectorizer()
    vectors = vectorizer.fit_transform(
        documents + [request.question]
    )

    # Retrieve the document most relevant to the question
    similarities = cosine_similarity(
        vectors[-1], vectors[:-1]
    )[0]

    best_index = int(similarities.argmax())
    best_doc = security_docs[best_index]

    # Simple response constructed from retrieved information
    answer = (
        f"Topic: {best_doc['topic']}. "
        f"Based on the knowledge base: {best_doc['text']}"
    )

    return {
        "question": request.question,
        "retrieved_topic": best_doc["topic"],
        "relevance_score": round(
            float(similarities[best_index]), 3
        ),
        "answer": answer
    }

from pathlib import Path
import logging
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException


# Keep the encryption key and audit log in the project folder
BASE_DIR = Path(__file__).resolve().parent
KEY_FILE = BASE_DIR / "security.key"
AUDIT_FILE = BASE_DIR / "audit.log"

# Create a key once; do not replace it on every restart
if not KEY_FILE.exists():
    KEY_FILE.write_bytes(Fernet.generate_key())

cipher = Fernet(KEY_FILE.read_bytes())

# Configure security audit logging
security_logger = logging.getLogger("security_audit")
security_logger.setLevel(logging.INFO)

if not security_logger.handlers:
    handler = logging.FileHandler(AUDIT_FILE, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    )
    security_logger.addHandler(handler)
    security_logger.propagate = False


def record_audit(action):
    security_logger.info("%s", action)


class TextRequest(BaseModel):
    text: str


class CipherRequest(BaseModel):
    ciphertext: str


@app.post("/security/encrypt")
def encrypt_text(request: TextRequest):
    if not request.text.strip():
        raise HTTPException(
            status_code=400, detail="Text cannot be empty"
        )

    encrypted = cipher.encrypt(request.text.encode("utf-8")).decode("utf-8")
    record_audit("Text encrypted successfully")

    return {
        "message": "Encryption successful",
        "ciphertext": encrypted
    }


@app.post("/security/decrypt")
def decrypt_text(request: CipherRequest):
    try:
        decrypted = cipher.decrypt(
            request.ciphertext.encode("utf-8")
        ).decode("utf-8")

        record_audit("Text decrypted successfully")
        return {"message": "Decryption successful", "text": decrypted}

    except (InvalidToken, ValueError):
        record_audit("Decryption failed: invalid ciphertext")
        raise HTTPException(
            status_code=400,
            detail="Invalid ciphertext or encryption key"
        )


@app.get("/security/audit-log")
def get_audit_log():
    if not AUDIT_FILE.exists():
        return {"events": []}

    events = AUDIT_FILE.read_text(
        encoding="utf-8"
    ).splitlines()

    return {"events": events[-20:]}

