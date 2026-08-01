import datetime
import queue
import threading
import time
from collections import defaultdict
from datetime import datetime

class SecurityAnalyzer(threading.Thread):
    def __init__(self, parsed_queue, stop_event):
        super().__init__(name = "Security-Analyzer")
        self.parsed_queue = parsed_queue
        self.stop_event = stop_event

        self.ip_counter = defaultdict(list)
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

                # if the ip is already banned, we don't care about it
                if ip in self.blocked_ips:
                    continue

                # save the time
                timestamp = log_data["timestamp"]
                datetime_timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                ip_time = datetime_timestamp.timestamp()
                self.ip_counter[ip].append(ip_time)

                # contains only times in the last 3 seconds
                self.ip_counter[ip] = [t for t in self.ip_counter[ip] if ip_time - t <= self.TIME_WIDNDOW]

                request_counter = len(self.ip_counter[ip])
                if request_counter >= self.THRESHOLD:
                    print(f"[{self.name}] 🚨🚨 DDoS! 🚨🚨")
                    print(f"[{self.name}] IP BANNED: {ip} ({request_counter} req/sec)")
                    self.blocked_ips.add(ip)
            except queue.Empty:
                pass
            except Exception as e:
                print(f"[{self.name}] ❌ Error: {e}")

        print(f"[{self.name}] Turning off. Total blocked IP: {len(self.blocked_ips)}")