import json
import subprocess
import time
import threading
import streamlit as st
import pandas as pd
import plotly.express as px
import socket
from datetime import datetime, timedelta
from pathlib import Path
import logging
from typing import List, Dict, Optional, Tuple
import sys

LOG_DIR = Path('logs')
DATA_DIR = Path('data')
LOG_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

BLOCKLIST_FILE = DATA_DIR / 'blocklist.json'
ACTIONS_LOG = LOG_DIR / 'actions.log'
FIREWALL_CMD = '/sbin/iptables'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(ACTIONS_LOG),
        logging.StreamHandler()
    ]
)

def execute_firewall_command(cmd: List[str]) -> Tuple[bool, str]:
    try:
        result = subprocess.run(
            ['sudo'] + cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=10
        )
        return True, ""
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed ({' '.join(cmd)}): {e.stderr}"
        logging.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logging.error(error_msg)
        return False, error_msg

def block_ip(ip: str) -> bool:
    """Block an IP address for both incoming and outgoing traffic."""
    success_in, _ = execute_firewall_command([FIREWALL_CMD, '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
    success_out, _ = execute_firewall_command([FIREWALL_CMD, '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'])
    
    if success_in or success_out:
        log_action(ip, 'blocked')
    return success_in and success_out

def unblock_ip(ip: str) -> bool:
    """Unblock an IP address for both incoming and outgoing traffic."""
    success_in, _ = execute_firewall_command([FIREWALL_CMD, '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
    success_out, _ = execute_firewall_command([FIREWALL_CMD, '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'])

    if success_in or success_out:
        log_action(ip, 'unblocked')
    return success_in and success_out

def log_action(ip: str, action: str) -> None:
    timestamp = datetime.now().isoformat()
    log_entry = {"time": timestamp, "ip": ip, "action": action}

    with open(ACTIONS_LOG, 'a') as log_file:
        json.dump(log_entry, log_file)
        log_file.write('\n')

    try:
        blocklist = load_blocklist()
    except Exception as e:
        logging.error(f"Error loading blocklist: {str(e)}")
        blocklist = []

    blocklist.append(log_entry)
    save_blocklist(blocklist)

def load_blocklist() -> List[Dict]:
    try:
        with open(BLOCKLIST_FILE, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_blocklist(data: List[Dict]) -> None:
    with open(BLOCKLIST_FILE, 'w') as file:
        json.dump(data, file, indent=4)

# ===================== Auto-Unblock System =====================
class AutoUnblocker(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True
        self.check_interval = 60

    def run(self):
        while self.running:
            try:
                self.check_expired_blocks()
            except Exception as e:
                logging.error(f"Auto-unblock error: {str(e)}")
            time.sleep(self.check_interval)

    def check_expired_blocks(self):
        blocklist = load_blocklist()
        updated_list = []
        now = datetime.now()

        for entry in blocklist:
            if entry['action'] != 'blocked':
                updated_list.append(entry)
                continue

            blocked_time = datetime.fromisoformat(entry['time'])
            unblock_time = blocked_time + timedelta(hours=1)

            if now > unblock_time:
                if unblock_ip(entry['ip']):
                    logging.info(f"Auto-unblocked IP: {entry['ip']}")
                else:
                    updated_list.append(entry)
            else:
                updated_list.append(entry)

        save_blocklist(updated_list)

# ===================== Visualization & Reporting =====================
def get_blocked_ips_data() -> pd.DataFrame:
    try:
        blocklist = load_blocklist()
        df = pd.DataFrame(blocklist)
        if not df.empty:
            df['time'] = pd.to_datetime(df['time'])
        return df
    except Exception as e:
        logging.error(f"Error loading blocked IP data: {str(e)}")
        return pd.DataFrame()

def visualize_blocked_ips():
    df = get_blocked_ips_data()
    if df.empty:
        st.warning("No blocked IPs to visualize.")
        return

    blocked = df[df['action'] == 'blocked']
    if blocked.empty:
        st.warning("No currently blocked IPs.")
        return

    fig = px.timeline(
        blocked,
        x_start="time",
        x_end="time",
        y="ip",
        title="Blocked IPs Timeline",
        labels={"ip": "IP Address", "time": "Block Time"}
    )
    st.plotly_chart(fig)

    st.subheader("Blocking Statistics")
    col1, col2 = st.columns(2)
    col1.metric("Total Blocks", len(blocked))
    col2.metric("Unique IPs", blocked['ip'].nunique())

# ===================== DNS Lookup =====================
def lookup_ips(domain: str) -> List[str]:
    try:
        if not domain:
            raise ValueError("Domain cannot be empty")

        results = socket.getaddrinfo(domain, None)
        ips = list({result[4][0] for result in results})
        return ips if ips else []
    except Exception as e:
        logging.error(f"DNS lookup failed for {domain}: {str(e)}")
        return []

def init_session_state():
    if 'domain_ips' not in st.session_state:
        st.session_state.domain_ips = []
    if 'unblocker' not in st.session_state:
        st.session_state.unblocker = AutoUnblocker()
        st.session_state.unblocker.start()

def show_manual_blocking():
    st.subheader("Manual IP Management")
    ip = st.text_input("Enter IP Address:", key="manual_ip")
    
    col1, col2 = st.columns(2)
    if col1.button("Block IP"):
        if ip:
            if block_ip(ip):
                st.success(f"IP {ip} blocked successfully!")
                st.rerun()
            else:
                st.error(f"Failed to block IP {ip}")
        else:
            st.error("Please enter a valid IP address")

    if col2.button("Unblock IP"):
        if ip:
            if unblock_ip(ip):
                st.success(f"IP {ip} unblocked successfully!")
                st.rerun()
            else:
                st.error(f"Failed to unblock IP {ip}")
        else:
            st.error("Please enter a valid IP address")

def show_domain_lookup():
    st.subheader("Domain IP Lookup")
    domain = st.text_input("Enter Domain (e.g., google.com):", key="domain_input")
    
    if st.button("Lookup IPs"):
        if domain:
            ips = lookup_ips(domain)
            if ips:
                st.session_state.domain_ips = ips
                st.success(f"Found {len(ips)} IP addresses")
            else:
                st.warning("No IP addresses found for this domain")
        else:
            st.warning("Please enter a domain name")

    if st.session_state.domain_ips:
        selected_ip = st.selectbox(
            "Select IP to block:",
            st.session_state.domain_ips,
            key="ip_select"
        )
        if st.button("Block Selected IP"):
            if block_ip(selected_ip):
                st.success(f"IP {selected_ip} blocked successfully!")
                st.rerun()
            else:
                st.error(f"Failed to block IP {selected_ip}")

def show_blocked_ips():
    st.subheader("Blocked IPs Overview")
    visualize_blocked_ips()

    if st.checkbox("Show raw blocked IP data"):
        df = get_blocked_ips_data()
        if not df.empty:
            st.dataframe(df.sort_values('time', ascending=False))
        else:
            st.info("No blocked IP data available")

def main():
    st.set_page_config(
        page_title="Block Watch — Real-Time IP Defense",
        page_icon="🛡️",
        layout="wide"
    )
    
    st.title("🛡️ Block Watch — Real-Time IP Defense")
    st.markdown("A comprehensive tool for blocking and monitoring IP addresses.")
    
    init_session_state()
    
    tab1, tab2, tab3 = st.tabs(["Manual Blocking", "Domain Lookup", "Blocked IPs"])
    
    with tab1:
        show_manual_blocking()
    
    with tab2:
        show_domain_lookup()
    
    with tab3:
        show_blocked_ips()
    
    st.sidebar.header("System Information")
    st.sidebar.code(f"Python: {sys.version.split()[0]}")
    st.sidebar.code(f"Streamlit: {st.__version__}")
    
    if st.sidebar.checkbox("Show logs"):
        st.sidebar.subheader("Recent Logs")
        try:
            with open(ACTIONS_LOG, 'r') as f:
                logs = f.readlines()[-20:]
            st.sidebar.code(''.join(logs))
        except FileNotFoundError:
            st.sidebar.warning("No log file found")

if __name__ == "__main__":
    main()
