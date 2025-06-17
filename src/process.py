import collections
import threading
import time
import os
import psutil
import signal
import subprocess

from aes import Decryptor
from utils.logger import log_info, log_error
from utils.hash import Hasher, SHAType

RELEASE: bool = False;

class ProcessHandler:
#public
    def __init__(self, interval: int = 10, permited_processes: int = 10, permited_files_accesed: int = 10):
        log_info(f'[INFO] Setting up "ProcessHandler"');
        self._interval:               int = interval;
        self._permited_processes:     int = permited_processes;
        self._permited_files_accesed: int = permited_files_accesed;

        self._malware_paths: list[str] = [];
        self._monitor_thread           = None;
        self._malware_event            = threading.Event();
        signal.signal(signal.SIGINT, self.__signal_handler)

        self._time_init = time.time();

        self._jigsaw_processes_names: list[str] = ["firefox.exe", "drpbx.exe", "jigsaw.exe", "host.exe"];
        self._malware_hashes:         list[str] = ["3ae96f73d805e1d3995253db4d910300d8442ea603737a1428b613061e7f61e7"];
        self._legic_processes:        list[str] = [ "System",
                                                    "System Idle Process",
                                                    "csrss.exe",
                                                    "wininit.exe",
                                                    "winlogon.exe",
                                                    "smss.exe",
                                                    "services.exe",
                                                    "lsass.exe",
                                                    "svchost.exe",
                                                    "explorer.exe",
                                                    "spoolsv.exe",
                                                    "dwm.exe",
                                                    "ctfmon.exe",
                                                    "taskhostw.exe",
                                                    "fontdrvhost.exe",
                                                    "audiodg.exe",
                                                    "sihost.exe",
                                                    "RuntimeBroker.exe",
                                                    "SearchIndexer.exe",
                                                    "SearchApp.exe",
                                                    "StartMenuExperienceHost.exe",
                                                    "ShellExperienceHost.exe" ];
    
    def set_interval(self, interval: int):
        self._interval = interval;

    def set_permited_processes(self, permited_processes: int):
        self._permited_processes = permited_processes;

    def set_permited_files_accesed(self, permited_files_accesed: int):
        self._permited_files_accesed = permited_files_accesed;
#public
    def start_monitor(self):
        self._monitor_thread = threading.Thread(target=self.__scan_processes, daemon=True);
        self._monitor_thread.start();
#private
    def __signal_handler(self, sig, frame):
        self.__stop()

    def __scan_processes (self):
        while not self._malware_event.is_set():
            processes = list(psutil.process_iter(['pid', 'name', 'exe']));
            processes_pids = collections.defaultdict(list);

            self.__detection_by_process_name(processes, processes_pids);
            self.__detection_by_process_count(processes_pids);
            self.__detection_by_process_hash(processes);

            if self._malware_paths:
                self.__notify();

            self.__check_time_to_go();
            time.sleep(self._interval);

    def __detection_by_process_name(self, processes, processes_pids):
        for process in processes:
            try:
                name: str = process.info['name'];
                pid: int = process.info['pid'];
                processes_pids[name].append(pid);

                exe_path = process.info['exe'];
                if name in self._jigsaw_processes_names and exe_path:
                    log_info(f"\n[WARNING] Detected malicious process: {name} (PID: {pid})");
                    if RELEASE:
                        psutil.Process(pid).kill();
                    log_info("[SUCCESS] Process detained");
                    self._malware_paths.append(str(exe_path));
            except Exception as e:
                log_error(f"[ERROR] Error while detaining the process {name}: {e}");


    def __detection_by_process_count(self, processes_pids):
        for name, pids in processes_pids.items():
            if len(pids) > self._permited_processes and not self._legic_processes.count(name):
                log_info(f"\n[WARNING, MULTIPLE STANCES] {name} - PIDS number: {len(pids)}.");
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
                exe_path: str = process.info['exe'];
                if exe_path:
                    hasher.set_file_path(exe_path);
                    file_hash = hasher.digest();
                    if file_hash in self._malware_hashes:
                        pid: int = process.info['pid'];
                        log_info(f"\n[WARNING, HASH MATCH] Malicious process detected: {exe_path} (PID: {pid})");

                        if RELEASE:
                            psutil.Process(pid).kill();
                        log_info(f"{exe_path} - PID {pid} killed.");
                        self._malware_paths.append(str(exe_path));
            except Exception as e:
                log_error(f"[ERROR] Error while detaining the process {exe_path}: {e}");
    
    def __delete_malware(self):
            log_info(f"[INFO] Removing malware");
            for path in self._malware_paths:
                try:
                    if RELEASE:
                        os.remove(path);
                except Exception as e:
                    log_error(f"[ERROR] Error while deleting malware. Trying with PowerShell.");
                    try:
                        subprocess.run(
                            ["powershell", "-Command", f"Remove-Item -Path '{path}' -Force"],
                            check=True
                        )
                        print("Archivo eliminado.")
                    except subprocess.CalledProcessError as e:
                        print(f"No se pudo eliminar el archivo: {e}")

            log_info(f"[SUCCESS] Malware obliterated");
    
    def __decrypt_files(self):
        decrypter: Decryptor = Decryptor();
        if RELEASE:
            decrypter.search_and_destroy();

    def __check_time_to_go(self):
        if(time.time() - self._time_init >= 300):
            self.__stop();
    
    def __notify(self):
        self.__stop();
        self.__delete_malware();
        self.__decrypt_files();

    def __stop(self):
        self._malware_event.set();