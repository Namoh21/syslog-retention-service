"""
Windows Service wrapper using pywin32.
Registers main.py (uvicorn/FastAPI) as a native Windows service.

Usage (run as Administrator):
    python windows_service.py install   -- register the service
    python windows_service.py start     -- start it
    python windows_service.py stop      -- stop it
    python windows_service.py remove    -- unregister it
    python windows_service.py restart   -- stop then start
    python windows_service.py status    -- print current status
"""
import os
import subprocess
import sys
import time
from pathlib import Path

import servicemanager
import win32event
import win32service
import win32serviceutil


SERVICE_NAME = "SyslogRetentionSvc"
SERVICE_DISPLAY = "Syslog Retention and SIEM Service"
SERVICE_DESC = "Syslog receiver and SIEM for Unifi Dream Machine. Web console on port 8080."

# The directory that contains this file
BASE_DIR = Path(__file__).parent


class SyslogService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY
    _svc_description_ = SERVICE_DESC

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self._stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._process = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self._stop_event)
        if self._process:
            self._process.terminate()

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self._run()
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, ""),
        )

    def _run(self):
        python_exe = Path(sys.executable)
        main_script = BASE_DIR / "main.py"
        log_dir = BASE_DIR / "logs"
        log_dir.mkdir(exist_ok=True)
        stdout_log = open(log_dir / "service.log", "a", buffering=1)
        stderr_log = open(log_dir / "service_err.log", "a", buffering=1)

        while True:
            self._process = subprocess.Popen(
                [str(python_exe), str(main_script)],
                cwd=str(BASE_DIR),
                stdout=stdout_log,
                stderr=stderr_log,
            )
            # Wait for either the process to exit or a stop signal
            handles = [self._stop_event]
            while self._process.poll() is None:
                rc = win32event.WaitForSingleObject(self._stop_event, 1000)
                if rc == win32event.WAIT_OBJECT_0:
                    self._process.terminate()
                    stdout_log.close()
                    stderr_log.close()
                    return
            # Process exited on its own - check stop signal before restarting
            rc = win32event.WaitForSingleObject(self._stop_event, 0)
            if rc == win32event.WAIT_OBJECT_0:
                stdout_log.close()
                stderr_log.close()
                return
            # Auto-restart after a brief pause
            time.sleep(5)


def _get_status():
    try:
        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1]
        states = {
            win32service.SERVICE_STOPPED: "Stopped",
            win32service.SERVICE_START_PENDING: "Starting",
            win32service.SERVICE_STOP_PENDING: "Stopping",
            win32service.SERVICE_RUNNING: "Running",
            win32service.SERVICE_PAUSED: "Paused",
        }
        return states.get(status, f"Unknown ({status})")
    except Exception:
        return "Not installed"


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Called by the SCM
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SyslogService)
        servicemanager.StartServiceCtrlDispatcher()
    elif len(sys.argv) == 2 and sys.argv[1] == "status":
        print(f"Service '{SERVICE_NAME}': {_get_status()}")
    else:
        win32serviceutil.HandleCommandLine(SyslogService)
