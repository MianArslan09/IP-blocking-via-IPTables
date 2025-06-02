# 🛡️ Block Watch — Real-Time IP Defense

A comprehensive, real-time IP blocking and monitoring system built with Python and Streamlit. It offers manual and automated IP blocking/unblocking using Linux `iptables`, with integrated DNS lookup, logging, and interactive visualization using Plotly.

---

## 🚀 Features

- 🔒 **Manual IP Blocking/Unblocking**
- 🌐 **Domain-to-IP Lookup with Blocking**
- ⏱️ **Auto-Unblock after 1 Hour**
- 📈 **Interactive Visualizations of Blocked IPs**
- 📜 **Logging to File (JSON)**
- 📁 **Persistent Storage of Block History**
- 🧠 **Multi-threaded Auto-Unblock System**
- 🔎 **Show Raw Data + Logs Viewer**
- 🐧 Designed for **Linux Systems** using `iptables`

---

## 🧰 Requirements

- Python 3.8+
- `iptables` (Pre-installed on most Linux distros)
- `sudo` privileges
- Required Python packages:
  - `streamlit`
  - `pandas`
  - `plotly`

---

## ⚙️ Installation

1. **Clone the Repository**

```bash
git clone https://github.com/your-username/block-watch.git
cd block-watch
