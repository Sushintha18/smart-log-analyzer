import streamlit as st
import pandas as pd
import requests

st.set_page_config(
    page_title="Sentinel SOC | Security Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_URL = "http://127.0.0.1:8000"

# High-contrast, readable styling (avoid forcing white text on light backgrounds)
st.markdown("""
<style>
    .stApp { background: #f4f7fb; color: #172b4d; }
    .block-container { padding-top: 1.2rem; padding-bottom: 2rem; }
    [data-testid="stSidebar"] { background: #142236; }
    [data-testid="stSidebar"] * { color: #f3f6fb; }
    .brand { font-size: 1.3rem; font-weight: 800; }
    .hero {
        background: linear-gradient(115deg, #132238, #28547a);
        border-radius: 14px; padding: 24px 28px; margin-bottom: 18px;
        color: #ffffff;
    }
    .hero h1 { color: #ffffff !important; font-size: 1.9rem; margin: 0 0 8px 0; }
    .hero p { color: #e2ecf7 !important; margin: 0; }
    h1, h2, h3, h4, p, label, .stMarkdown { color: #172b4d; }
    [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3, [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] label { color: #f3f6fb; }
    .metric-card {
        background: #ffffff; border: 1px solid #dce4ee; border-radius: 12px;
        padding: 16px; min-height: 110px;
    }
    .metric-label { color: #53657d !important; font-size: .82rem; font-weight: 700; }
    .metric-value { color: #132238 !important; font-size: 1.8rem; font-weight: 800; }
    .metric-note { color: #64748b !important; font-size: .76rem; }
    div[data-testid="stMetric"] {
        background: #ffffff; border: 1px solid #dce4ee;
        border-radius: 10px; padding: 12px;
    }
    div[data-testid="stMetric"] label,
    div[data-testid="stMetric"] [data-testid="stMetricValue"] {
        color: #132238 !important;
    }
    div.stButton > button, div.stDownloadButton > button {
        border-radius: 8px; font-weight: 650; min-height: 2.6rem;
    }
    [data-testid="stExpander"] {
        background: #ffffff; border: 1px solid #dce4ee; border-radius: 9px;
    }
    [data-testid="stDataFrame"] { background: #ffffff; }
    .small-note { color: #53657d !important; font-size: .9rem; }
</style>
""", unsafe_allow_html=True)


# Simple demo login: authenticate before showing the dashboard.
# Demo credentials: admin / sentinel123
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    st.markdown("""
    <div style="max-width:620px;margin:3rem auto 1rem auto;text-align:center;">
      <div style="font-size:3rem;">🛡️</div>
      <h1 style="color:#132238 !important;">SENTINEL SOC</h1>
      <p style="color:#53657d !important;">Smart Cloud-Based Security Log Analyzer</p>
    </div>
    """, unsafe_allow_html=True)
    left, center, right = st.columns([1, 1.2, 1])
    with center:
        with st.form("login_form"):
            st.subheader("Sign in")
            username = st.text_input("Username", placeholder="Enter username")
            password = st.text_input("Password", type="password", placeholder="Enter password")
            submitted = st.form_submit_button("Login", use_container_width=True, type="primary")
        if submitted:
            if username == "admin" and password == "sentinel123":
                st.session_state["authenticated"] = True
                st.rerun()
            else:
                st.error("Incorrect username or password. Please try again.")
        st.caption("Demo login: admin / sentinel123")
    st.stop()



def api_call(method, path, **kwargs):
    timeout = kwargs.pop("timeout", 15)
    response = requests.request(method, f"{API_URL}{path}", timeout=timeout, **kwargs)
    response.raise_for_status()
    return response.json()


def normalize_data(raw):
    external = {"masked_user", "action", "source_ip", "access_result"}
    standard = {"user", "event", "ip_address"}

    if external.issubset(raw.columns):
        data = raw.copy()
        data["user"] = data["masked_user"].fillna("").astype(str)
        data["ip_address"] = data["source_ip"].fillna("").astype(str)
        action = data["action"].fillna("").astype(str)
        result = data["access_result"].fillna("").astype(str)
        data["event"] = action + " - " + result

        is_login = action.str.lower().str.contains(r"login|log in|auth", regex=True, na=False)
        failed = result.str.lower().str.contains(
            r"fail|denied|blocked|reject|unsuccessful", regex=True, na=False
        )
        data.loc[is_login & failed, "event"] = "Login Failed - " + action[is_login & failed]
        return data

    if standard.issubset(raw.columns):
        return raw.copy()

    raise ValueError(
        "Unsupported CSV. Required columns: user, event, ip_address OR "
        "masked_user, action, source_ip, access_result."
    )


def classify_data(data):
    out = data.copy()
    event = out["event"].fillna("").astype(str).str.lower()
    ip = out["ip_address"].fillna("").astype(str)

    out["priority"] = "LOW"
    out["reason"] = "Routine event; continue monitoring."
    out["recommended_action"] = "Retain the log and continue monitoring."

    failed = event.str.contains(r"login failed|failed login", regex=True, na=False)
    unauthorized = event.str.contains(r"unauthorized|access denied", regex=True, na=False)
    sensitive_failed = (
        event.str.contains(r"delete|modify|upload|download", regex=True, na=False)
        & event.str.contains(r"fail|failure|denied|blocked|reject", regex=True, na=False)
    )

    out.loc[failed, ["priority", "reason", "recommended_action"]] = [
        "MEDIUM",
        "Login failure recorded.",
        "Review the account and source IP; check for repeated attempts.",
    ]
    out.loc[unauthorized, ["priority", "reason", "recommended_action"]] = [
        "HIGH",
        "Unauthorized or denied access wording detected.",
        "Verify permissions and inspect related account/resource activity.",
    ]
    out.loc[sensitive_failed, ["priority", "reason", "recommended_action"]] = [
        "HIGH",
        "A sensitive operation has a failed or denied result.",
        "Inspect the resource and related events; validate before taking action.",
    ]

    counts = ip[failed].value_counts()
    repeated_ips = counts[counts >= 3].index
    repeated = failed & ip.isin(repeated_ips)
    out.loc[repeated, ["priority", "reason", "recommended_action"]] = [
        "HIGH",
        "Three or more login failures from the same source IP.",
        "Investigate the source IP and account; consider rate limiting after validation.",
    ]

    malicious = pd.Series(False, index=out.index)
    if "target" in out.columns:
        target = out["target"].fillna("").astype(str).str.lower()
        malicious = target.isin(["malicious", "attack", "anomaly", "1", "true"])
        out.loc[malicious, ["priority", "reason", "recommended_action"]] = [
            "HIGH",
            "The supplied dataset labels this record malicious; validate the label and context.",
            "Prioritize analyst review and inspect surrounding events before containment.",
        ]

    high_bin = pd.Series(False, index=out.index)
    if "anomaly_bin" in out.columns:
        high_bin = out["anomaly_bin"].fillna("").astype(str).str.lower().eq("high")
        out.loc[high_bin, ["priority", "reason", "recommended_action"]] = [
            "HIGH",
            "The dataset marks this row as a high anomaly category.",
            "Review the event and related records; validate before taking action.",
        ]

    high_score = pd.Series(False, index=out.index)
    if "anomaly_score" in out.columns:
        score = pd.to_numeric(out["anomaly_score"], errors="coerce")
        high_score = score >= 0.80
        out.loc[high_score, ["priority", "reason", "recommended_action"]] = [
            "HIGH",
            "The dataset anomaly score is at least 0.80.",
            "Investigate the score with surrounding context; a score alone is not proof of an attack.",
        ]

    critical = malicious & high_bin & high_score
    out.loc[critical, ["priority", "reason", "recommended_action"]] = [
        "CRITICAL",
        "Dataset malicious label, high anomaly category and high score coincide.",
        "Immediate analyst review: validate evidence and follow incident-response policy if confirmed.",
    ]

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    out["_order"] = out["priority"].map(order)
    return out.sort_values("_order").reset_index(drop=True)


def assistant_local_answer(question):
    q = question.lower()
    if any(x in q for x in ["login", "password", "brute force", "failed"]):
        return (
            "Repeated login failures may indicate password guessing. Review source IPs "
            "and targeted accounts, apply rate limiting, enable MFA, and follow the "
            "organization's incident-response procedure."
        )
    if any(x in q for x in ["unauthorized", "permission", "access"]):
        return (
            "Verify the account and resource permissions, apply least privilege, and "
            "inspect surrounding events for unexpected access."
        )
    if any(x in q for x in ["encrypt", "encryption", "key"]):
        return (
            "Use authenticated encryption, protect keys separately from encrypted data, "
            "restrict key access, and never commit secrets to source control."
        )
    if any(x in q for x in ["aws", "cloud", "iam"]):
        return (
            "For an AWS deployment, apply IAM least privilege, enable CloudTrail, use "
            "CloudWatch for monitoring, and protect encryption keys with managed key services."
        )
    return (
        "Validate the alert, inspect related logs and account activity, assess impact, "
        "document findings, and treat automated alerts as investigation leads until confirmed."
    )



def build_incident_queue(triage_frame):
    """Collapse repeated log rows into one incident per IP, priority and reason."""
    frame = triage_frame.copy()
    keys = ["priority", "ip_address", "reason", "recommended_action"]
    grouped_rows = []

    for _, group in frame.groupby(keys, dropna=False, sort=False):
        first = group.iloc[0].copy()
        first["occurrences"] = int(len(group))
        first["users_affected"] = ", ".join(
            sorted(set(group["user"].fillna("").astype(str)) - {""})
        )
        first["event_types"] = ", ".join(
            sorted(set(group["event"].fillna("").astype(str)) - {""})
        )
        if "timestamp" in group.columns:
            first["first_seen"] = str(group["timestamp"].iloc[0])
            first["last_seen"] = str(group["timestamp"].iloc[-1])
        grouped_rows.append(first)

    if not grouped_rows:
        return pd.DataFrame(columns=list(frame.columns) + ["occurrences", "users_affected", "event_types"])

    result = pd.DataFrame(grouped_rows).reset_index(drop=True)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    result["_order"] = result["priority"].map(order)
    return result.sort_values(["_order", "occurrences"], ascending=[True, False]).reset_index(drop=True)


# Sidebar
with st.sidebar:
    st.markdown('<div class="brand">🛡️ SENTINEL SOC</div>', unsafe_allow_html=True)
    st.caption("Security Log Intelligence")
    if st.button("Log out", use_container_width=True):
        st.session_state["authenticated"] = False
        st.rerun()
    st.divider()
    page = st.radio(
        "NAVIGATION",
        [
            "Overview",
            "Incident Queue",
            "Investigate Event",
            "Analytics & Report",
            "Security Assistant",
            "Security Tools",
            "System Information",
        ],
        key="page_navigation",
    )
    st.divider()
    st.markdown("**DATA SOURCE**")
    uploaded = st.file_uploader("Upload CSV logs", type=["csv"], key="csv_upload")
    if st.button("Check API connection", use_container_width=True):
        try:
            result = api_call("GET", "/health", timeout=5)
            st.session_state["api_health"] = f"Connected ({result.get('status', 'healthy')})"
        except Exception as exc:
            st.session_state["api_health"] = f"Not connected: {exc}"
    if st.session_state.get("api_health"):
        if st.session_state["api_health"].startswith("Connected"):
            st.success(st.session_state["api_health"])
        else:
            st.warning(st.session_state["api_health"])

# Load sample or uploaded data
sample = pd.DataFrame({
    "user": ["Alice", "Bob", "Bob", "Bob", "Admin", "Alice"],
    "event": ["Login Success", "Login Failed", "Login Failed",
              "Login Failed", "Unauthorized Access", "Login Success"],
    "ip_address": ["192.168.1.2", "10.0.0.5", "10.0.0.5",
                   "10.0.0.5", "172.16.0.8", "192.168.1.2"],
})
source_name = "Built-in sample data"

try:
    data = normalize_data(pd.read_csv(uploaded)) if uploaded else sample.copy()
    if uploaded:
        source_name = uploaded.name
except Exception as exc:
    st.error(str(exc))
    st.stop()

for col in ["user", "event", "ip_address"]:
    data[col] = data[col].fillna("").astype(str).str.strip()
data = data[(data["user"] != "") & (data["event"] != "") & (data["ip_address"] != "")].reset_index(drop=True)
triage = classify_data(data)
incident_queue = build_incident_queue(triage)

event_lower = triage["event"].str.lower()
failed_count = int(event_lower.str.contains(r"login failed|failed login", regex=True, na=False).sum())
unauthorized_count = int(event_lower.str.contains(r"unauthorized|access denied", regex=True, na=False).sum())
critical_count = int((triage["priority"] == "CRITICAL").sum())
high_count = int((triage["priority"] == "HIGH").sum())
medium_count = int((triage["priority"] == "MEDIUM").sum())

st.markdown("""
<div class="hero">
    <h1>Security Operations Center</h1>
    <p>Security event monitoring · Incident triage · Investigation workflow</p>
</div>
""", unsafe_allow_html=True)
st.caption(f"Source: {source_name}  |  Records loaded: {len(triage):,}")

# Overview
if page == "Overview":
    st.subheader("Overview")
    st.write("A concise view of the current security signals and investigation priorities.")
    cols = st.columns(5)
    cards = [
        ("TOTAL EVENTS", f"{len(triage):,}", "Records loaded"),
        ("CRITICAL", f"{critical_count:,}", "Immediate analyst review"),
        ("HIGH PRIORITY", f"{high_count:,}", "Investigate promptly"),
        ("FAILED LOGINS", f"{failed_count:,}", "Authentication signals"),
        ("UNAUTHORIZED", f"{unauthorized_count:,}", "Access-related signals"),
    ]
    for col, (label, value, note) in zip(cols, cards):
        with col:
            st.markdown(
                f'<div class="metric-card"><div class="metric-label">{label}</div>'
                f'<div class="metric-value">{value}</div><div class="metric-note">{note}</div></div>',
                unsafe_allow_html=True,
            )
    st.divider()
    left, right = st.columns(2)
    with left:
        st.markdown("#### Priority distribution")
        st.bar_chart(triage["priority"].value_counts().reindex(
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"], fill_value=0
        ))
    with right:
        st.markdown("#### Most common events")
        st.bar_chart(triage["event"].value_counts().head(10))
    st.markdown("#### Incidents to review first")
    urgent = incident_queue[incident_queue["priority"].isin(["CRITICAL", "HIGH"])].head(10)
    if urgent.empty:
        st.success("No Critical or High events were identified by the current rules.")
    else:
        cols = [c for c in ["priority", "ip_address", "occurrences", "users_affected", "event_types", "reason"] if c in urgent.columns]
        st.dataframe(urgent[cols], use_container_width=True, hide_index=True)
    st.info("These are triage signals, not definitive proof of a successful attack.")

# Incident Queue
elif page == "Incident Queue":
    st.subheader("Incident Queue")
    st.write("Related log rows are consolidated into incidents to avoid repeated alerts.")

    priorities = st.multiselect(
        "Priority",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM"],
    )
    search = st.text_input("Search IP, user, event or reason")
    queue = incident_queue[incident_queue["priority"].isin(priorities)].copy()

    if search.strip():
        mask = queue.astype(str).apply(
            lambda col: col.str.contains(search.strip(), case=False, na=False)
        ).any(axis=1)
        queue = queue[mask]

    st.caption(f"{len(queue):,} consolidated incident(s) match the filters")
    show_cols = [
        c for c in [
            "priority", "ip_address", "occurrences", "users_affected",
            "event_types", "reason"
        ] if c in queue.columns
    ]

    if queue.empty:
        st.success("No incidents match your filters.")
    else:
        st.dataframe(queue[show_cols], use_container_width=True, hide_index=True)
        st.markdown("#### Recommended actions")
        for _, row in queue.head(30).iterrows():
            count = int(row.get("occurrences", 1))
            with st.expander(
                f"{row['priority']} | {row['ip_address']} | {count} related log(s)"
            ):
                st.write("**Source IP:**", row["ip_address"])
                st.write("**Related log entries:**", count)
                st.write("**Event types:**", row.get("event_types", row.get("event", "")))
                st.write("**Users affected:**", row.get("users_affected", row.get("user", "Not available")))
                st.write("**Reason:**", row["reason"])
                st.write("**Next step:**", row["recommended_action"])
                if "first_seen" in row.index:
                    st.write("**First seen:**", row["first_seen"])
                    st.write("**Last seen:**", row["last_seen"])

# Investigate Event
elif page == "Investigate Event":
    st.subheader("Investigate Event")
    st.write("Choose an event to inspect its reason, risk level and response recommendation.")
    if triage.empty:
        st.info("No events are available.")
    else:
        chosen = st.selectbox(
            "Event",
            triage.index.tolist(),
            format_func=lambda i: f"{triage.loc[i, 'priority']} | {triage.loc[i, 'ip_address']} | {triage.loc[i, 'event']}",
        )
        row = triage.loc[chosen]
        if row["priority"] == "CRITICAL":
            st.error("CRITICAL — immediate analyst review recommended")
        elif row["priority"] == "HIGH":
            st.warning("HIGH — investigate promptly")
        elif row["priority"] == "MEDIUM":
            st.info("MEDIUM — review and monitor")
        else:
            st.success("LOW — routine monitoring")
        left, right = st.columns(2)
        with left:
            st.markdown("#### Why flagged")
            st.write(row["reason"])
            st.markdown("#### Recommended response")
            st.write(row["recommended_action"])
        with right:
            st.markdown("#### Event details")
            detail = row.drop(labels=["_order"], errors="ignore")
            st.json({str(k): None if pd.isna(v) else str(v) for k, v in detail.items()})

# Analytics & Report
elif page == "Analytics & Report":
    st.subheader("Analytics & Report")
    st.write("View local statistics, optionally run backend ML analysis, or download the triage report.")
    c1, c2, c3 = st.columns(3)
    c1.metric("Records", f"{len(triage):,}")
    c2.metric("Distinct IPs", f"{triage['ip_address'].nunique():,}")
    c3.metric("Distinct users", f"{triage['user'].nunique():,}")
    left, right = st.columns(2)
    with left:
        st.markdown("#### Event frequency")
        st.bar_chart(triage["event"].value_counts().head(15))
    with right:
        st.markdown("#### Priority breakdown")
        st.bar_chart(triage["priority"].value_counts().reindex(
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"], fill_value=0
        ))
    if st.button("Run FastAPI ML analysis", type="primary"):
        try:
            logs = triage[["user", "event", "ip_address"]].fillna("").to_dict(orient="records")
            result = api_call("POST", "/analytics", json={"logs": logs}, timeout=60)
            st.success("Backend analytics completed.")
            st.metric("Rows processed by backend", result.get("cleaned_rows", 0))
            if result.get("event_counts"):
                st.markdown("#### Backend event counts")
                st.bar_chart(result["event_counts"])
            if result.get("ip_analysis"):
                st.dataframe(pd.DataFrame(result["ip_analysis"]), use_container_width=True, hide_index=True)
            st.info(result.get("ml_message", "Analysis completed."))
        except Exception as exc:
            st.error(f"Backend analytics unavailable: {exc}")
    st.download_button(
        "Download triage report (CSV)",
        data=triage.drop(columns=["_order"], errors="ignore").to_csv(index=False).encode("utf-8"),
        file_name="security_triage_report.csv",
        mime="text/csv",
    )

# Security Assistant
elif page == "Security Assistant":
    st.subheader("Security Assistant")
    st.write("Get practical guidance for triage and investigation.")
    question = st.text_input(
        "Ask a security question",
        value="How should I investigate repeated failed logins?",
        key="security_question",
    )
    if st.button("Get guidance", type="primary"):
        if not question.strip():
            st.warning("Enter a question first.")
        else:
            answer = None
            try:
                result = api_call("POST", "/ask", json={"question": question}, timeout=15)
                answer = result.get("answer")
                if answer:
                    st.success("Retrieved guidance from FastAPI.")
                    st.caption(f"Topic: {result.get('retrieved_topic', 'Unknown')} | Relevance: {result.get('relevance_score', 'N/A')}")
            except Exception:
                pass
            if not answer:
                answer = assistant_local_answer(question)
                st.info("Using built-in guidance because the API was unavailable.")
            st.markdown("#### Guidance")
            st.write(answer)
    st.caption("This is TF-IDF retrieval with a local fallback, not a generative LLM.")

# Security Tools
elif page == "Security Tools":
    st.subheader("Security Tools")
    st.markdown("#### Encrypt and decrypt text")
    plaintext = st.text_area("Text to encrypt", "Security incident requires investigation")
    if st.button("Encrypt text", type="primary"):
        if not plaintext.strip():
            st.warning("Enter text first.")
        else:
            try:
                result = api_call("POST", "/security/encrypt", json={"text": plaintext}, timeout=10)
                st.session_state["ciphertext"] = result["ciphertext"]
                st.success("Encryption completed.")
            except Exception as exc:
                st.error(f"Encryption unavailable: {exc}")
    if st.session_state.get("ciphertext"):
        st.markdown("**Encrypted ciphertext**")
        st.code(st.session_state["ciphertext"])
        if st.button("Decrypt saved ciphertext"):
            try:
                result = api_call(
                    "POST", "/security/decrypt",
                    json={"ciphertext": st.session_state["ciphertext"]},
                    timeout=10,
                )
                st.success("Decryption completed.")
                st.write("Recovered text:", result.get("text", ""))
            except Exception as exc:
                st.error(f"Decryption unavailable: {exc}")
    st.divider()
    if st.button("Load security audit log"):
        try:
            result = api_call("GET", "/security/audit-log", timeout=10)
            events = result.get("events", [])
            if events:
                for event in events:
                    st.text(event)
            else:
                st.info("No audit events recorded yet.")
        except Exception as exc:
            st.error(f"Audit log unavailable: {exc}")

# System Information
elif page == "System Information":
    st.subheader("System Information")
    st.markdown("""
    - **Dashboard:** Streamlit
    - **Data processing:** Pandas
    - **Backend API:** FastAPI
    - **Anomaly detection:** Scikit-learn Isolation Forest endpoint
    - **Knowledge retrieval:** TF-IDF over a small local knowledge base
    - **Encryption:** Fernet through the backend
    - **Audit trail:** Local log file
    """)
    st.warning(
        "AWS services, automatic IP blocking and a generative LLM are not connected in this prototype. "
        "Alerts are investigation leads; validate before declaring a confirmed attack."
    )

st.divider()
st.caption("Sentinel SOC | Security Log Analysis Prototype")
