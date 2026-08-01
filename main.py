import multiprocessing as mp
import threading
import queue
import time  # Aggiungi questo

from TrafficGenerator import TrafficGenerator
from LogParser import LogParser
from SecurityAnalyzer import SecurityAnalyzer

POISON_PILL = "KILL_SIGNAL"

if __name__ == "__main__":
    raw_log_queue = mp.Queue(maxsize=1000)
    parsed_log_queue = mp.Queue(maxsize=1000)
    stop_event = threading.Event()

    # 1. Avvio Generatore
    gen = TrafficGenerator(1, raw_log_queue, stop_event)
    gen.start()

    # 2. Avvio dei 2 Parser (Processi)
    parsers = []
    for i in range(2):
        p = LogParser(i + 1, raw_log_queue, parsed_log_queue)
        p.start()
        parsers.append(p)

    # 3. AVVIO DEL SECURITY ANALYZER (Thread)
    analyzer = SecurityAnalyzer(parsed_log_queue, stop_event)
    analyzer.start()

    try:
        # Ora il main thread non fa nulla, si mette in pausa e lascia lavorare
        # la pipeline (Generatore -> Parser -> Analyzer) per 10 secondi.
        print("--- SISTEMA ONLINE: In ascolto per 10 secondi ---")
        time.sleep(10)

    except KeyboardInterrupt:
        print("\nInterruzione manuale rilevata.")

    finally:
        print("\n--- SHUTDOWN START ---")

        # 1. Fermiamo Thread (Generatore e Analyzer ascoltano lo stesso stop_event!)
        stop_event.set()
        gen.join()
        analyzer.join()  # <-- Aggiunto questo
        print("[Orchestratore] Generatore e Analyzer fermati.")

        # 2. Fermiamo i Processi (Parser) con le pillole
        for _ in range(len(parsers)):
            raw_log_queue.put(POISON_PILL)

        for p in parsers:
            p.join()
        print("[Orchestratore] Tutti i Parser fermati.")

        print("--- CLOSING SYSTEM ---")