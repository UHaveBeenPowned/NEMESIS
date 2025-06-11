from utils.logger import log_info, log_error
from process import ProcessHandler

def main():
    log_info("Configuring NEMESIS utilities...");

    process_handler: ProcessHandler = ProcessHandler();
    
    log_info("NEMESIS running");

    try:
        process_handler.scan_processes();
    except KeyboardInterrupt:
        log_info("NEMESIS says: I will come back.");

if __name__ == "__main__":
    main();