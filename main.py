import multiprocessing as mp
import threading
import queue
import time

from TrafficGenerator import TrafficGenerator
from LogParser import LogParser
from SecurityAnalyzer import SecurityAnalyzer
from AlertDispatcher import AlertDispatcher

POISON_PILL = "KILL_SIGNAL"

if __name__ == "__main__":
    raw_log_queue = mp.Queue(maxsize=1000)
    parsed_log_queue = mp.Queue(maxsize=1000)

    alert_queue = queue.Queue(maxsize=100)

    stop_event = threading.Event()

    gen = TrafficGenerator(1, raw_log_queue, stop_event)
    gen.start()

    parsers = []
    for i in range(2):
        p = LogParser(i + 1, raw_log_queue, parsed_log_queue)
        p.start()
        parsers.append(p)

    # Sending the alert_queue to the analyzer
    analyzer = SecurityAnalyzer(parsed_log_queue, alert_queue, stop_event)
    analyzer.start()

    # Starting dispatcher
    dispatcher = AlertDispatcher(alert_queue, stop_event)
    dispatcher.start()

    try:
        print("--- ONLINE: On hear for 10 seconds ---")
        time.sleep(10)

    except KeyboardInterrupt:
        pass

    finally:
        print("\n--- SHUTDOWN START ---")

        stop_event.set()
        gen.join()
        analyzer.join()
        dispatcher.join()  # <--- STOPPING THE DISPATCHER
        print("[Otchestrator] Generator, Analyzer and Dispatcher stopped.")

        for _ in range(len(parsers)):
            raw_log_queue.put(POISON_PILL)

        for p in parsers:
            p.join()
        print("[Orchestrator] All Parsers stopped.")

        print("--- CLOSING SYSTEM ---")