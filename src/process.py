import time
import psutil
from utils.logger import log_info, log_error

class ProcessHandler:
#public
    def __init__(self, interval: int = 10):
        log_info(f'Setting up "ProcessHandler"');
        self._interval: int = interval;
        self._jigsaw_processes_names: [str] = ["firefox.exe", "drpbx.exe", "jigsaw.exe", "host.exe"];
#public
    def detection_by_process_name(self):
        while True:
            for process in psutil.process_iter(['pid', 'name']):
                try:
                    name: str = process.info['name'];
                    if name in self._jigsaw_processes_names:
                        pid: int = process.info['pid'];
                        log_info(f"Detected malicious process: {name} (PID: {pid})");

                        psutil.Process(pid).kill();
                        log_info("Process detained");
                except Exception as e:
                    log_error(f"Error while detaining the process {name}: {e}");
            time.sleep(self._interval);
            
    def set_interval(interval: int):
        self._interval = interval;