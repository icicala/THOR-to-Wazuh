#!/usr/bin/env python3
import json, logging, os, shutil, sys, time, ctypes, struct
import signal
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional
import select
import threading

PATH_BASE = Path("/var/ossec/logs/thor_json_reports")
DROP_ZONE = PATH_BASE / "drop_zone"
MONITORED_ZONE = PATH_BASE / "monitored_zone"
MONITORED_FILE = MONITORED_ZONE / "thor_normalized.json"
ARCHIVE = PATH_BASE / "archive"
LOGFILE = "/var/ossec/logs/thor_etl.log"
WAZUH_USER = "wazuh"
WAZUH_GROUP = "wazuh"
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO = 0x00000080
EVENT_STRUCT = struct.Struct("iIII")
BUF_LEN = 1024 * EVENT_STRUCT.size



def setup_logging() -> None:
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(
        LOGFILE,
        maxBytes=10_485_760,
        backupCount=5
    )
    formatter = logging.Formatter("thor_etl: %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def set_wazuh_permissions(path: Path) -> None:
    try:
        shutil.chown(path, user=WAZUH_USER, group=WAZUH_GROUP)
        os.chmod(path, 0o750 if path.is_dir() else 0o640)
    except Exception as e:
        logging.error(f"Failed to set permissions on {path}: {e}")
        raise


def expand_object_lists(obj: Any) -> Any:
    if not isinstance(obj, dict):
        return obj

    expanded: Dict[str, Any] = {}
    for key, value in obj.items():
        if isinstance(value, list) and value and all(isinstance(i, dict) for i in value):
            for index, item in enumerate(value, 1):
                expanded[f"{key}_{index}"] = expand_object_lists(item)
        elif isinstance(value, dict):
            expanded[key] = expand_object_lists(value)
        else:
            expanded[key] = value
    return expanded


def normalize_log_line(raw_line: str) -> Optional[str]:
    try:
        return json.dumps(expand_object_lists(json.loads(raw_line)),
                          separators=(',', ':')) + '\n'
    except Exception as e:
        logging.warning(f"Malformed line skipped: {e}")
        return None


def process_file(source_file: Path) -> None:
    logging.info(f"Processing {source_file.name}")
    try:
        with source_file.open() as src, MONITORED_FILE.open('a') as dst:
            for line in src:
                normalized = normalize_log_line(line)
                if normalized:
                    dst.write(normalized)

        archive_date = time.strftime("%Y-%m-%d")
        archive_dir = ARCHIVE / archive_date
        archive_dir.mkdir(parents=True, exist_ok=True)
        set_wazuh_permissions(archive_dir)

        source_file.rename(archive_dir / source_file.name)
        logging.info(f"Processed {source_file.name} → {archive_dir}")
    except Exception as e:
        logging.error(f"Failed to process {source_file.name}: {e}")


def setup_directory_structure() -> None:
    for directory in (DROP_ZONE, MONITORED_ZONE, ARCHIVE):
        directory.mkdir(parents=True, exist_ok=True)
        set_wazuh_permissions(directory)

    MONITORED_FILE.touch(exist_ok=True)
    set_wazuh_permissions(MONITORED_FILE)

    Path(LOGFILE).touch(exist_ok=True)
    set_wazuh_permissions(Path(LOGFILE))


def watch_drop_zone() -> None:

    libc = ctypes.CDLL('libc.so.6', use_errno=True)

    inotify_fd = libc.inotify_init1(0)
    if inotify_fd < 0:
        logging.error(f"Failed to initialize inotify: {os.strerror(ctypes.get_errno())}")
        sys.exit(1)

    watch_id = libc.inotify_add_watch(inotify_fd, str(DROP_ZONE).encode(), IN_CLOSE_WRITE | IN_MOVED_TO)
    if watch_id < 0:
        logging.error(f"Failed to add watch: {os.strerror(ctypes.get_errno())}")
        os.close(inotify_fd)
        sys.exit(1)

    stop_event = threading.Event()

    def signal_handler(signal_num, _):
        logging.info(f"Received signal {signal_num}, shutting down")
        stop_event.set()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    for json_file in DROP_ZONE.glob("*.json"):
        logging.info(f"Processing existing file: {json_file.name}")
        process_file(json_file)

    logging.info(f"Watching {DROP_ZONE} for new JSON files")
    try:
        while not stop_event.is_set():
            if select.select([inotify_fd], [], [], 1.0)[0]:
                event_buffer = os.read(inotify_fd, BUF_LEN)
                buffer_pos = 0
                while buffer_pos + EVENT_STRUCT.size <= len(event_buffer):
                    event_wd, event_mask, _, name_len = EVENT_STRUCT.unpack_from(event_buffer, buffer_pos)
                    buffer_pos += EVENT_STRUCT.size
                    filename = event_buffer[buffer_pos:buffer_pos + name_len].split(b'\0', 1)[0].decode()
                    buffer_pos += name_len

                    if filename.endswith(".json"):
                        file_path = DROP_ZONE / filename
                        if file_path.exists():
                            logging.info(f"New file detected: {filename}")
                            process_file(file_path)
    finally:
        logging.info("Cleaning up inotify resources")
        libc.inotify_rm_watch(inotify_fd, watch_id)
        os.close(inotify_fd)

def main() -> None:
    setup_logging()
    setup_directory_structure()
    logging.info(f"Watching {DROP_ZONE} → {MONITORED_FILE} (inotify mode)")
    watch_drop_zone()


if __name__ == "__main__":
    main()