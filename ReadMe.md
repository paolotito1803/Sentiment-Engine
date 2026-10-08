# 🛡️ Sentinel: Real-Time Concurrent IDS (Intrusion Detection System)

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Concurrency](https://img.shields.io/badge/architecture-multiprocessing%20%7C%20threading-success)
![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)

A high-performance, real-time log analysis and intrusion detection engine built entirely with Python's standard library.

This project demonstrates advanced software engineering concepts, specifically designed to overcome the Python **GIL (Global Interpreter Lock)** by using a hybrid architecture of `multiprocessing` and `threading` based on the **Producer-Consumer** design pattern.

## ✨ Key Features

* **Hybrid Concurrency Model:** Uses threads for I/O-bound tasks (Log Generation, Alert Dispatching) and processes for CPU-bound tasks (Regex parsing).
* **Deep Packet Inspection:** Extracts endpoints, IPs, and HTTP methods from raw logs using pre-compiled Regular Expressions (Named Capturing Groups).
* **Dynamic Threat Scoring:** Implements a custom *Leaky Bucket* algorithm. IPs accumulate points for suspicious activities (e.g., SQL Injections, Brute Force) and lose points over time.
* **Graceful Shutdown:** Implements `threading.Event()` and the **Poison Pill** pattern to safely spin down the system without data loss or deadlocks.
* **Event-Driven Dispatching:** Alerts are handled asynchronously without blocking the main threat-analysis engine.

## 🏗️ Architecture Pipeline

The system is fully decoupled and scalable. Data flows through secure Inter-Process Communication (IPC) queues:

```text
[Traffic Generators] (Threads)
        │
        ▼  (Raw Log Queue)
        │
[Regex Parsers] (Processes) ──► Extracts JSON data
        │
        ▼  (Parsed Log Queue)
        │
[Security Analyzer] (Thread) ──► Threat Scoring (Leaky Bucket)
        │
        ▼  (Alert Queue)
        │
[Alert Dispatcher] (Thread) ──► Saves to .log & Simulates Webhook
```

## 🚀 Quick Start

This project requires **zero external dependencies**. It relies strictly on Python's built-in libraries.


### 1. Run the orchestrator

```bash
python main.py
```

### 2. Check the alerts

When an attack is detected, the system will automatically create and populate a `security_alerts.log` file in the root directory.

## 📂 Project Structure

* **`main.py`**: The central orchestrator. Wires up queues, initializes workers, and handles the Graceful Shutdown.
* **`TrafficGenerator.py`**: Simulates background server traffic and injects malicious spikes (DDoS, SQLi).
* **`LogParser.py`**: CPU-bound workers that compile regex patterns and parse raw strings into structured Python dictionaries.
* **`SecurityAnalyzer.py`**: The brain of the IDS. Tracks IP history and calculates threat scores on the fly.
* **`AlertDispatcher.py`**: Simulates network I/O to send alerts via webhooks and writes to persistent storage.

## 📊 Example Output

When a malicious payload (e.g., SQL Injection) is detected, the console will output:

```text
[Security-Analyzer] 🚨🚨 THREAT DETECTED! 🚨🚨
[Security-Analyzer] IP BANNED: 10.0.0.99 (Score: 110) - Reason: Possible SQL Injection
[Alert-Dispatcher] 📨 Sending Webhook notify to the Security team for IP: 10.0.0.99
[Alert-Dispatcher] ✅ Sent correctly!
```
