import collections
import time
import psutil
from utils.logger import log_info, log_error
from utils.hash import Hasher, SHAType

RELEASE: bool = False;

class ProcessHandler:
#public
    def __init__(self, interval: int = 10, permited_processes: int = 10, permited_files_accesed: int = 10):
        log_info(f'Setting up "ProcessHandler"');
        self._interval:               int = interval;
        self._permited_processes:     int = permited_processes;
        self._permited_files_accesed: int = permited_files_accesed;
        self._jigsaw_processes_names: list[str] = ["firefox.exe", "drpbx.exe", "jigsaw.exe", "host.exe"];
        self._malware_hashes = ["3ae96f73d805e1d3995253db4d910300d8442ea603737a1428b613061e7f61e7", "5973578d37bb09686acc82b2677ea29401409757843bdd685c1773cf93d63d8c"];
    
    def set_interval(self, interval: int):
        self._interval = interval;

    def set_permited_processes(self, permited_processes: int):
        self._permited_processes = permited_processes;

    def set_permited_files_accesed(self, permited_files_accesed: int):
        self._permited_files_accesed = permited_files_accesed;
#public
    def scan_processes (self):
        while True:
            processes = list(psutil.process_iter(['pid', 'name', 'exe']));
            processes_pids = collections.defaultdict(list);

            self.__detection_by_process_name(processes, processes_pids);
            self.__detection_by_process_count(processes, processes_pids);
            self.__detection_by_process_hash(processes);
            time.sleep(self._interval);

    def __detection_by_process_name(self, processes, processes_pids):
        for process in processes:
            try:
                name: str = process.info['name'];
                pid: int = process.info['pid'];
                processes_pids[name].append(pid)

                if name in self._jigsaw_processes_names:
                    log_info(f"[WARNING] Detected malicious process: {name} (PID: {pid})");
                    if RELEASE:
                        psutil.Process(pid).kill();
                    log_info("[SUCCESS] Process detained");
            except Exception as e:
                log_error(f"[ERROR] Error while detaining the process {name}: {e}");

    def __detection_by_process_count(self, processes, processes_pids):
        for name, pids in processes_pids.items():
            if len(pids) > self._permited_processes:
                log_info(f"[WARNING, MULTIPLE STANCES] {name} - PIDS number: {len(pids)}.");
                for pid in pids:
                    try:
                        if RELEASE:
                            psutil.Process(pid).kill(); 
                        log_info(f"{name} - PID {pid} killed.");
                    except Exception as e:
                        log_error(f"[ERROR] Error while detaining the process {name}: {e}");

    def __detection_by_process_hash(self, processes):
        hasher: Hasher = Hasher(SHAType.SHA_256);

        for process in processes:
            try:
                name: str = process.info['exe'];
                if name:
                    hasher.set_file_path(name);
                    file_hash = hasher.digest();
                    if file_hash in self._malware_hashes:
                        pid: int = process.info['pid'];
                        log_info(f"[WARNING, HASH MATCH] Malicious process detected: {name} (PID: {pid})");

                        if RELEASE:
                            psutil.Process(pid).kill();
                        log_info(f"{name} - PID {pid} killed.");
            except Exception as e:
                log_error(f"[ERROR] Error while detaining the process {name}: {e}");
