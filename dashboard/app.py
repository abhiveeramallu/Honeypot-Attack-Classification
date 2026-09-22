"""Phase 5: Streamlit analytics dashboard over classified Cowrie sessions.

Run with:
    streamlit run app.py -- --db ../data/sqlite/sessions.db

Pages (sidebar nav): Executive Summary, ATT&CK Matrix, Session Explorer,
IoC / Payload Vault.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

sys.path.append(str(Path(__file__).resolve().parent.parent / "features"))
from attack_rules import technique_lookup  # noqa: E402

st.set_page_config(page_title="Honeypot ATT&CK Dashboard", layout="wide")


def _cli_db_path() -> tuple[Path, str]:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=Path(__file__).resolve().parent.parent / "data/sqlite/sessions.db")
    parser.add_argument("--table", default="sessions")
    args, _ = parser.parse_known_args(sys.argv[1:])
    return args.db, args.table


@st.cache_data(ttl=60)
def load_sessions(db_path: str, table: str) -> pd.DataFrame:
    with sqlite3.connect(db_path) as conn:
        df = pd.read_sql_query(f"SELECT * FROM {table}", conn)

    for col in ["command_sequence", "urls_downloaded", "file_hashes"]:
        if col in df.columns:
            df[col + "_list"] = df[col].apply(lambda s: _safe_json(s))

    tech_col = "predicted_techniques" if "predicted_techniques" in df.columns else "rule_techniques"
    df["techniques_list"] = df[tech_col].apply(_safe_json) if tech_col in df.columns else [[]] * len(df)
    df["start_time_parsed"] = pd.to_datetime(df.get("start_time"), errors="coerce", utc=True)
    return df


def _safe_json(s):
    try:
        return json.loads(s) if s else []
    except (TypeError, json.JSONDecodeError):
        return []


def _pseudo_geo(ip: str) -> tuple[float, float]:
    """Deterministic placeholder lat/lon derived from the IP so the map
    renders without a real GeoIP database. Replace with MaxMind GeoLite2 (or
    an internal GeoIP service) for real attacker geolocation."""
    h = int(hashlib.sha256(ip.encode()).hexdigest(), 16)
    lat = (h % 18000) / 100 - 90
    lon = ((h // 18000) % 36000) / 100 - 180
    return lat, lon


def page_executive_summary(df: pd.DataFrame) -> None:
    st.title("Executive Summary")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Sessions", len(df))
    col2.metric("Unique Attacker IPs", df["src_ip"].nunique())
    col3.metric("Successful Logins", int(df.get("login_success", pd.Series(dtype=int)).astype(bool).sum()))
    col4.metric("Payloads Captured", int(df["file_hashes_list"].apply(len).sum()) if "file_hashes_list" in df else 0)

    st.subheader("Top Credential Pairs")
    creds = df.dropna(subset=["username", "password"])
    if not creds.empty:
        top_creds = (
            creds.groupby(["username", "password"]).size().reset_index(name="count")
            .sort_values("count", ascending=False).head(15)
        )
        st.dataframe(top_creds, width="stretch")
    else:
        st.info("No credential attempts recorded.")

    st.subheader("Sessions Over Time")
    if df["start_time_parsed"].notna().any():
        by_day = df.dropna(subset=["start_time_parsed"]).set_index("start_time_parsed").resample("1D").size()
        st.plotly_chart(px.bar(by_day, labels={"value": "sessions", "start_time_parsed": "day"}), width="stretch")

    st.subheader("Attacker Geo-Origin (approximate)")
    if df["src_ip"].notna().any():
        geo_df = df.dropna(subset=["src_ip"]).drop_duplicates("src_ip").copy()
        geo_df[["lat", "lon"]] = geo_df["src_ip"].apply(lambda ip: pd.Series(_pseudo_geo(ip)))
        st.map(geo_df[["lat", "lon"]])
        st.caption(
            "Coordinates are a deterministic placeholder derived from the IP, not a real "
            "lookup — wire in MaxMind GeoLite2 (or your SIEM's enrichment) for accurate geolocation."
        )


def page_attack_matrix(df: pd.DataFrame) -> None:
    st.title("ATT&CK Matrix View")
    lookup = technique_lookup()

    exploded = df.explode("techniques_list").dropna(subset=["techniques_list"])
    if exploded.empty:
        st.info("No classified techniques yet. Run the rule engine or ML classifier first.")
        return

    exploded["technique_name"] = exploded["techniques_list"].map(lambda t: lookup.get(t, (t, "?"))[0])
    exploded["tactic"] = exploded["techniques_list"].map(lambda t: lookup.get(t, (t, "?"))[1])
    exploded["day"] = exploded["start_time_parsed"].dt.date

    st.subheader("Technique Frequency")
    freq = exploded.groupby(["techniques_list", "technique_name", "tactic"]).size().reset_index(name="sessions")
    freq = freq.sort_values("sessions", ascending=False)
    st.plotly_chart(
        px.bar(freq, x="techniques_list", y="sessions", color="tactic", hover_data=["technique_name"],
               labels={"techniques_list": "Technique ID"}),
        width="stretch",
    )

    st.subheader("Technique Heatmap Over Time")
    if exploded["day"].notna().any():
        heat = exploded.groupby(["day", "techniques_list"]).size().reset_index(name="count")
        pivot = heat.pivot(index="techniques_list", columns="day", values="count").fillna(0)
        st.plotly_chart(px.imshow(pivot, aspect="auto", labels={"color": "sessions"}), width="stretch")

    st.subheader("Raw technique table")
    st.dataframe(freq, width="stretch")


def page_session_explorer(df: pd.DataFrame) -> None:
    st.title("Session Explorer")
    lookup = technique_lookup()

    session_ids = df["session_id"].tolist()
    if not session_ids:
        st.info("No sessions available.")
        return

    selected = st.selectbox("Session ID", session_ids)
    row = df[df["session_id"] == selected].iloc[0]

    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("Raw Terminal Log")
        commands = row.get("command_sequence_list", [])
        st.code("\n".join(commands) if commands else "(no commands captured)", language="bash")

    with col2:
        st.subheader("Session Info")
        st.write({
            "src_ip": row.get("src_ip"),
            "protocol": row.get("protocol"),
            "username": row.get("username"),
            "password": row.get("password"),
            "login_attempts": int(row.get("login_attempts") or 0),
            "login_success": bool(row.get("login_success")),
            "duration_sec": float(row.get("session_duration") or 0),
        })

        st.subheader("Auto-Tagged ATT&CK Techniques")
        techniques = row.get("techniques_list", [])
        if techniques:
            for tid in techniques:
                name, tactic = lookup.get(tid, (tid, "?"))
                st.markdown(f"- **{tid}** — {name} _( {tactic} )_")
        else:
            st.write("None detected.")

        if "source" in row.index and pd.notna(row.get("source")):
            source = row["source"]
            confidence = row.get("confidence")
            label = "ML model" if source == "ml" else "rule engine (ML confidence was below threshold)"
            conf_str = f", confidence {float(confidence):.2f}" if pd.notna(confidence) else ""
            st.caption(f"Classified by: {label}{conf_str}")


def page_ioc_vault(df: pd.DataFrame) -> None:
    st.title("IoC / Payload Vault")

    urls = df.explode("urls_downloaded_list").dropna(subset=["urls_downloaded_list"])
    hashes = df.explode("file_hashes_list").dropna(subset=["file_hashes_list"])

    st.subheader("Fetched URLs")
    if not urls.empty:
        st.dataframe(urls[["session_id", "src_ip", "urls_downloaded_list"]].rename(
            columns={"urls_downloaded_list": "url"}), width="stretch")
    else:
        st.info("No downloads captured yet.")

    st.subheader("Payload Hashes")
    if not hashes.empty:
        st.dataframe(hashes[["session_id", "src_ip", "file_hashes_list"]].rename(
            columns={"file_hashes_list": "sha256"}), width="stretch")
    else:
        st.info("No file hashes captured yet.")

    st.subheader("IoC Feed")
    ioc_csv = Path(__file__).resolve().parent.parent / "data" / "ioc_feed.csv"
    if ioc_csv.exists():
        ioc_bytes = ioc_csv.read_text()
        st.download_button("Download IoC feed (CSV)", ioc_bytes, file_name="ioc_feed.csv", key="dl_ioc_feed")
        st.dataframe(pd.read_csv(ioc_csv), width="stretch")
    else:
        st.info("No IoC feed generated yet. Run detection/generate_sigma.py or run_pipeline.py.")

    st.subheader("Sigma Rule Drafts")
    sigma_dir = Path(__file__).resolve().parent.parent / "detection" / "sigma_rules"
    if sigma_dir.exists():
        rule_files = sorted(sigma_dir.glob("*.yml"))
        if rule_files:
            for rf in rule_files:
                with st.expander(rf.name):
                    st.code(rf.read_text(), language="yaml")
                    st.download_button("Download", rf.read_text(), file_name=rf.name, key=f"dl_{rf.name}")
        else:
            st.info("No Sigma rules generated yet. Run detection/generate_sigma.py.")
    else:
        st.info("Sigma rules directory not found yet — run detection/generate_sigma.py.")


def main() -> None:
    db_path, table = _cli_db_path()
    if not db_path.exists():
        st.error(f"Database not found: {db_path}. Run etl/etl_parser.py first.")
        return

    df = load_sessions(str(db_path), table)

    st.sidebar.title("Honeypot ATT&CK Dashboard")
    page = st.sidebar.radio(
        "Page", ["Executive Summary", "ATT&CK Matrix", "Session Explorer", "IoC / Payload Vault"]
    )
    st.sidebar.caption(f"Data source: {db_path}")
    st.sidebar.caption("Auto-refreshes every 60s; click below to pick up a pipeline run immediately.")
    if st.sidebar.button("Refresh data now"):
        st.cache_data.clear()
        st.rerun()

    if page == "Executive Summary":
        page_executive_summary(df)
    elif page == "ATT&CK Matrix":
        page_attack_matrix(df)
    elif page == "Session Explorer":
        page_session_explorer(df)
    elif page == "IoC / Payload Vault":
        page_ioc_vault(df)


if __name__ == "__main__":
    main()
