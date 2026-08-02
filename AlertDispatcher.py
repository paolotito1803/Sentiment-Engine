import json
import queue
import threading
import time


class AlertDispatcher(threading.Thread):
    def __init__(self, alert_queue, stop_event):
        super().__init__(name = "Alert-Dispatcher")
        self.alert_queue = alert_queue
        self.stop_event = stop_event

    def run(self):
        print(f"{self.name} waiting emergency")
        while not self.stop_event.is_set():
            try:
                alert_data = self.alert_queue.get(timeout = 2) # waiting an alert
                # saving the result in a file.log
                with open("security_alert.log", "a") as f:
                    f.write(json.dumps(alert_data) + "\n")

                print(f"[{self.name}] 🚨 Alarm for IP {alert_data['attacker_ip']}")
                print(f"[{self.name}] 📨 Sending Webhook notify to the Security team ...")

                # time for HTTP request
                time.sleep(2)
                print(f"[{self.name}] ✅ Sent correctly {alert_data['attacker_ip']}!")
            except queue.Empty:
                pass
            except Exception as e:
                print(f"[{self.name}] ❌ ERROR: {e}")

        print(f"[{self.name}] Turning off completed.")