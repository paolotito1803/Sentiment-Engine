import datetime
import queue
import threading
import time
from collections import defaultdict
from datetime import datetime

class SecurityAnalyzer(threading.Thread):
    def __init__(self, parsed_queue, alert_queue, stop_event):
        super().__init__(name = "Security-Analyzer")
        self.parsed_queue = parsed_queue
        self.alert_queue = alert_queue
        self.stop_event = stop_event

        self.ip_counter = {}
        self.blocked_ips = set()

        # Security Rules
        self.THRESHOLD = 20
        self.TIME_WIDNDOW = 3

    def run(self):
        print(f"[{self.name}] Started. Real-Time traffic monitoring...")

        while not self.stop_event.is_set():
            try:
                log_data = self.parsed_queue.get(timeout = 2)
                ip = log_data["ip"]
                status = log_data["status"]
                endpoint = log_data["endpoint"]

                # if the ip is already banned, we don't care about it
                if ip in self.blocked_ips:
                    continue

                # save the time
                timestamp = log_data["timestamp"]
                datetime_timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                ip_time = datetime_timestamp.timestamp()
                self.ip_counter[ip].append(ip_time)

                if ip not in self.ip_counter:
                    self.ip_counter[ip] = {"score": "0.0", "last_seen": ip_time}
                else:
                    time_passed = ip_time - self.ip_counter[ip]["last_seen"]
                    score_losted = time_passed * self.THRESHOLD
                    score = self.ip_counter[ip]["score"]
                    self.ip_counter[ip]["score"] = max(0.0, score - score_losted)

                score_to_add = 1.0
                reason = "Anoulus volume (possible DDoS)"

                if status == 401 and "/api/login" in endpoint:
                    score_to_add = 50.0
                    reason = "Possible Brute Force"

                if "" in endpoint or "OR" in endpoint:
                    score_to_add = 20.0
                    reason = "Possible SQLi"

                self.ip_counter[ip]["score"] += score_to_add
                self.ip_counter[ip]["last_seen"] = ip_time

                final_score = self.ip_counter[ip]["score"]

                # contains only times in the last 3 seconds
                self.ip_counter[ip] = [t for t in self.ip_counter[ip] if ip_time - t <= self.TIME_WIDNDOW]

                request_counter = len(self.ip_counter[ip])
                if request_counter >= self.THRESHOLD:
                    alert_message = {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "attacker_ip": ip,
                        "intensity": f"{request_counter} req/sec",
                        "severity": "CRITICAL",
                        "description": "Possible DDOS attack"
                    }

                    self.alert_queue.put(alert_message)
                    print(f"[{self.name}] 🚨🚨 DDoS! 🚨🚨")
                    print(f"[{self.name}] IP BANNED: {ip} ({request_counter} req/sec)")
                    self.blocked_ips.add(ip)
            except queue.Empty:
                pass
            except Exception as e:
                print(f"[{self.name}] ❌ Error: {e}")

        print(f"[{self.name}] Turning off. Total blocked IP: {len(self.blocked_ips)}")