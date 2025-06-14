from folder_security import FolderSecurity
from process import ProcessHandler
from utils.logger import log_info, log_error
import time

def main():
    log_info("Configuring NEMESIS utilities...");

    process_handler: ProcessHandler = ProcessHandler();
    folder_security: FolderSecurity = FolderSecurity();

    log_info("NEMESIS running");

    try:
        folder_security.block_access();

        process_handler.start_monitor();
        while not process_handler._malware_event.is_set():
            time.sleep(1);
        folder_security.unlock_access();
    
    except KeyboardInterrupt:
        process_handler.stop();

    log_info("NEMESIS says: I will come back.");
    
if __name__ == "__main__":
    main();