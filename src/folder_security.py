import os
from pathlib import Path
import win32security
import win32file

from utils.logger import log_info, log_error

class FolderSecurity:
    def __init__(self):
        log_info(f'[INFO] Setting up "FolderSecurity"');
        self._everyone_account = self.__get_everyone_account();
        self._folders = [
            Path(os.getenv('USERPROFILE')) / "Documents",
            Path(os.getenv('USERPROFILE')) / "Downloads",
            Path(os.getenv('USERPROFILE')) / "Pictures",
            Path(os.getenv('USERPROFILE')) / "Videos",
            Path(os.getenv('USERPROFILE')) / "Music",
            Path(os.getenv('USERPROFILE')) / "AppData" / "Roaming"
        ];

    def block_access(self):
        for folder in self._folders:
            folder_str: str = str(folder);
            try:
                security_descriptor = win32security.GetFileSecurity(folder_str, win32security.DACL_SECURITY_INFORMATION);
                access_control_list = win32security.ACL();

                access_control_list.AddAccessDeniedAce(win32security.ACL_REVISION, win32file.FILE_ALL_ACCESS, self._everyone_account);
                security_descriptor.SetSecurityDescriptorDacl(1, access_control_list, 0);
                win32security.SetFileSecurity(folder_str, win32security.DACL_SECURITY_INFORMATION, security_descriptor);

                log_info(f"[SUCCESS] Secured folder: {folder_str}");
            except Exception as e:
                log_error(f"[ERROR] Error while protecting {folder_str}: {e}");

    def unlock_access(self):
        for folder in self._folders:
            folder_str: str = str(folder);
            try:
                security_descriptor = win32security.GetFileSecurity(folder_str, win32security.DACL_SECURITY_INFORMATION)
                access_control_list = win32security.ACL();

                access_control_list.AddAccessAllowedAce(win32security.ACL_REVISION, win32file.FILE_ALL_ACCESS, self._everyone_account)
                security_descriptor.SetSecurityDescriptorDacl(1, access_control_list, 0)
                win32security.SetFileSecurity(folder_str, win32security.DACL_SECURITY_INFORMATION, security_descriptor)

                log_info(f"[SUCCESS] Restored access: {folder_str}")
            except Exception as e:
                log_error(f"[ERROR] Error while restoring access of {folder_str}: {e}")


    def __get_everyone_account(self):
        everyone, _, _ = win32security.LookupAccountName("", "Todos");
        return everyone;