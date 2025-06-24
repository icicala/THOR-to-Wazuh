#!/usr/bin/env python3
import json, logging, os, shutil, sys, time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional

PATH_BASE = Path("/var/ossec/logs/thor_json_reports")
DROP_ZONE = PATH_BASE / "drop_zone"
ARCHIVE = PATH_BASE / "archive"
LOGFILE = "/var/ossec/logs/thor_etl.log"
BUFFER_SIZE = 1000
WAZUH_USER = "wazuh"
WAZUH_GROUP = "wazuh"

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
                          separators=(',', ':'))
    except Exception as e:
        logging.warning(f"Malformed line skipped: {e}")
        return None

def process_file(source_file: Path) -> None:
    logging.info(f"Processing {source_file.name}")
    try:
        buffer_lines = []
        with source_file.open(encoding="utf-8") as src:
            for raw_line in src:
                normalized = normalize_log_line(raw_line)
                if normalized:
                    buffer_lines.append(normalized)
                    if len(buffer_lines) >= BUFFER_SIZE:
                        sys.stdout.write("\n".join(buffer_lines) + "\n")
                        sys.stdout.flush()
                        buffer_lines.clear()
        if buffer_lines:
            sys.stdout.write("\n".join(buffer_lines) + "\n")
            sys.stdout.flush()

        archive_date = time.strftime("%Y-%m-%d")
        archive_dir = ARCHIVE / archive_date
        archive_dir.mkdir(parents=True, exist_ok=True)
        set_wazuh_permissions(archive_dir)

        source_file.rename(archive_dir / source_file.name)
        logging.info(f"Processed {source_file.name} → {archive_dir}")
    except Exception as e:
        logging.error(f"Failed to process {source_file.name}: {e}")

def setup_directory_structure() -> None:
    for directory in (DROP_ZONE, ARCHIVE):
        directory.mkdir(parents=True, exist_ok=True)
        set_wazuh_permissions(directory)

    Path(LOGFILE).touch(exist_ok=True)
    set_wazuh_permissions(Path(LOGFILE))

def main() -> None:
    setup_logging()
    setup_directory_structure()
    logging.info(f"Command-mode start; scanning {DROP_ZONE}")
    for json_file in DROP_ZONE.glob("*.json"):
        process_file(json_file)
    logging.info("Run complete")

if __name__ == "__main__":
    main()