import re
import multiprocessing as mp
import queue

POISON_PILL = "KILL_SIGNAL"

class LogParser(mp.Process):
    def __init__(self, parser_id : int, input_queue : mp.Queue, output_queue : mp.Queue):
        super().__init__(name = f"Parser = {parser_id}")
        self.input_queue = input_queue
        self.output_queue = output_queue

        regex_pattern = r'^(?P<ip>\S+) - - \[(?P<timestamp>.+?)\] "(?P<method>\S+) (?P<endpoint>.+?) HTTP/1\.1" (?P<status>\d{3})$'

        self.log_regex = re.compile(regex_pattern)

    def run(self):
        print(f"{self.name} started. Waiting ...")
        try:
            while True:
               try:
                   raw_log = self.input_queue.get(timeout = 2)
                   if raw_log == POISON_PILL:
                       print(f"[{self.name} Poison Pill, closing...")
                       break

                   match = self.log_regex.match(raw_log)
                   if match:
                       parsed_data = match.groupdict() # Extraction into a dictionary
                       parsed_data["status"] = int(parsed_data["status"])

                       self.output_queue.put(parsed_data)
                   else:
                       print(f"[{self.name} failure for: {raw_log}]")
               except queue.Empty:
                   continue
        except Exception as e:
            print(f"[{self.name} error {e}]")