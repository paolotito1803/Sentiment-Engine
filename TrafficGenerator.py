import random
import threading
import multiprocessing as mp
import time
from datetime import datetime
import queue

class TrafficGenerator(threading.Thread):
    def __init__(self, generator_id : int, shared_queue : mp.Queue, stop_event : threading.Event):
        super().__init__(name=f"generator = {generator_id}")
        self.generator_id = generator_id
        self.shared_queue = shared_queue
        self.stop_event = stop_event

        # bad and not bad IP generation
        self.normal_ips = [f"192.108.1.{i}" for i in range(10, 50)]
        self.attacker_ip = "10.0.0.99"

        # bad and not bad endpoints
        self.normal_endpoints = ["/index.html", "/images/logo.png", "/about", "/api/data"]
        self.attacker_endpoints = ["/api/login", "/?id=1' OR '1'='1", "/.env"]

        # methods type
        self.methods_type = ["GET", "POST", "PUT"]

    # function for generating casual logs
    def _generative_log_line(self, is_attack : bool = False) -> str:
        """Now construct a log string using Common Log Format"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if is_attack:
            ip = self.attacker_ip
            method = "POST"
            endpoint = random.choice(self.attacker_endpoints)
            status = random.choices([200, 401, 500], weights=[0.1, 0.8, 0.1])[0]
        else:
            ip = random.choice(self.normal_ips)
            method = random.choices(self.methods_type, weights=[0.8, 0.1, 0.1])[0]
            endpoint = random.choice(self.normal_endpoints)
            status = random.choices([200, 404, 301], weights=[0.8, 0.15, 0.05])[0]

        return f'{ip} - - [{timestamp}] "{method} {endpoint} HTTP/1.1" {status}'

    def run(self):
        print(f"[{self.name}] Started. Traffic generation ...")

        try:
            while not self.stop_event.is_set():
                try:
                    possible_attack = random.random() < 0.05

                    if possible_attack:
                    # generate logs
                        num_logs = random.randint(50, 100)
                        for _ in range(num_logs):
                            log_line = self._generative_log_line(is_attack = True)
                            # timeout used because if the queue is full the thread isn't stopped forever
                            self.shared_queue.put(log_line, timeout = 1)

                        print(f"[{self.name}] ⚠️ Attack ({num_logs} req)")
                    else: # nomral traffic
                        log_line = self._generative_log_line(is_attack = False)
                        self.shared_queue.put(log_line, timeout = 1)
                    time.sleep(random.uniform(0.01, 0.1))
                except  mp.queues.Full:
                    print(f"[{self.name}] Full queue! Wait!...")
                    time.sleep(0.5)
        except Exception as e:
            print(f"[{self.name}] ❌ CRITICAL ERROR: {e}")
        print(f"[{self.name}] stop_event received. Stopped.")