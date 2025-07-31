#!/usr/bin/env python3
import asyncio, contextlib, json, logging, logging.handlers, signal
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Callable, Awaitable

WAZUH_HOST = "127.0.0.1"
WAZUH_PORT = 514
THOR_LISTEN_HOST = "0.0.0.0"
THOR_LISTEN_PORT = 6515

THOR_ETL_LOG_FILE = "/var/log/thor_json.log"
MAX_LOG_FILE_SIZE = 20_971_520
LOG_BACKUP_COUNT = 5
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SEPARATOR_LINE = "#" * 60

THOR_EVENT_TAG = b"THOR:"
JSON_START_MARKER = b"{"

RECONNECT_DELAY = 3.0
MESSAGE_SIZE_LIMIT = 4 * 1024 * 1024
CONNECTION_BACKLOG = 4096

UTF8_ENCODING = "utf-8"
UTF8_STRICT_ERRORS = "strict"
JSON_COMPACT_SEPARATORS = (",", ":")
WHITESPACE_BYTE = b" "
NEWLINE_BYTE = b"\n"
CRLF_BYTES = b"\r\n"

class LoggingManager:
    def initialize_logging(self) -> None:
        rotating_logging = logging.handlers.RotatingFileHandler(
            THOR_ETL_LOG_FILE,
            maxBytes=MAX_LOG_FILE_SIZE,
            backupCount=LOG_BACKUP_COUNT,
            encoding=UTF8_ENCODING,
        )
        rotating_logging.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
        logging.basicConfig(level=logging.INFO, handlers=[rotating_logging], force=True)
        logging.info(SEPARATOR_LINE)
        logging.info(
            "THOR JSON SERVICE started – %s",
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        logging.info(
            "Listening on port %d, forwarding to %s:%d",
            THOR_LISTEN_PORT,
            WAZUH_HOST,
            WAZUH_PORT,
        )

class ServiceShutdownCoordinator:
    def __init__(self) -> None:
        self._shutdown_event = asyncio.Event()

    def request_service_shutdown(self) -> None:
        self._shutdown_event.set()

    def is_shutdown_requested(self) -> bool:
        return self._shutdown_event.is_set()

    async def wait_for_shutdown_signal(self):
        await self._shutdown_event.wait()

class SyslogJsonTransformer:
    def transform_thor_json_events(self, syslog_json: bytes) -> Optional[bytes]:
        thor_tag_position = syslog_json.find(THOR_EVENT_TAG)
        if thor_tag_position < 0:
            return None
        json_start_position = syslog_json.find(JSON_START_MARKER, thor_tag_position)
        if json_start_position < 0:
            return None
        try:
            json_object = json.loads(syslog_json[json_start_position:].decode(UTF8_ENCODING, UTF8_STRICT_ERRORS))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        expanded_json_object = self._expand_nested_json_lists(json_object)
        ensemble_json_bytes = json.dumps(expanded_json_object, separators=JSON_COMPACT_SEPARATORS).encode()
        return syslog_json[:json_start_position].rstrip() + WHITESPACE_BYTE + ensemble_json_bytes + NEWLINE_BYTE

    def _expand_nested_json_lists(self, json_object: Dict[str, Any]) -> Dict[str, Any]:
        expanded_properties = {}
        for property_key, property_value in json_object.items():
            if isinstance(property_value, list) and property_value and all(isinstance(item, dict) for item in property_value):
                for list_index, list_item in enumerate(property_value, 1):
                    expanded_properties[f"{property_key}_{list_index}"] = self._expand_nested_json_lists(list_item)
            elif isinstance(property_value, dict):
                expanded_properties[property_key] = self._expand_nested_json_lists(property_value)
            else:
                expanded_properties[property_key] = property_value
        return expanded_properties

class WazuhSyslogForwarder:
    def __init__(self, shutdown_coordinator: ServiceShutdownCoordinator) -> None:
        self._shutdown_coordinator = shutdown_coordinator
        self._wazuh_connection_writer: Optional[asyncio.StreamWriter] = None
        self._connection_lock = asyncio.Lock()
        self._dropped_thor_events_count = 0

    async def send_message_to_wazuh_server(self, message_bytes: bytes) -> None:
        try:
            writer = await self._get_wazuh_writer()
            writer.write(message_bytes)
            await asyncio.wait_for(writer.drain(), timeout=1.0)
        except (OSError, ConnectionError) as err:
            self._dropped_thor_events_count += 1
            logging.warning(
                "Wazuh send failed (%d dropped): %s",
                self._dropped_thor_events_count,
                err,
            )
            await self._close_wazuh_connection()

    async def _get_wazuh_writer(self) -> asyncio.StreamWriter:
        if self._wazuh_connection_writer and not self._wazuh_connection_writer.is_closing():
            return self._wazuh_connection_writer

        async with self._connection_lock:
            if self._wazuh_connection_writer and not self._wazuh_connection_writer.is_closing():
                return self._wazuh_connection_writer

            while not self._shutdown_coordinator.is_shutdown_requested():
                try:
                    _, self._wazuh_connection_writer = await asyncio.open_connection(WAZUH_HOST, WAZUH_PORT)
                    logging.info("Successfully connected to Wazuh at %s:%d", WAZUH_HOST, WAZUH_PORT)
                    return self._wazuh_connection_writer
                except OSError as connection_error:
                    logging.warning("Wazuh connect failed: %s - retrying in %.1fs", connection_error, RECONNECT_DELAY)
                    await asyncio.sleep(RECONNECT_DELAY)
            raise ConnectionError("Service shutdown in progress")

    async def _close_wazuh_connection(self):
        if self._wazuh_connection_writer:
            with contextlib.suppress(Exception):
                self._wazuh_connection_writer.close()
                await self._wazuh_connection_writer.wait_closed()
            self._wazuh_connection_writer = None

    async def shutdown_wazuh_forwarder_completely(self) -> None:
        await self._close_wazuh_connection()
        logging.info("WazuhSyslogForwarder shutdown completed")

class ThorClientConnectionHandler:
    def __init__(self,
                 syslog_json_transformer: SyslogJsonTransformer,
                 send_json_to_wazuh: Callable[[bytes], Awaitable[None]],
                 shutdown_coordinator: ServiceShutdownCoordinator) -> None:
        self._syslog_json_transformer = syslog_json_transformer
        self._send_json_to_wazuh = send_json_to_wazuh
        self._shutdown_coordinator = shutdown_coordinator
        self._thor_server: Optional[asyncio.Server] = None

    async def start_thor_server_listening(self) -> None:
        try:
            self._thor_server = await asyncio.start_server(
                self._handle_individual_thor_client_connection,
                host=THOR_LISTEN_HOST,
                port=THOR_LISTEN_PORT,
                limit=MESSAGE_SIZE_LIMIT,
                backlog=CONNECTION_BACKLOG
            )
            server_addresses = ", ".join(str(sock.getsockname()) for sock in self._thor_server.sockets)
            logging.info("THOR server listening on %s", server_addresses)
        except OSError as server_binding_error:
            logging.critical("Failed to bind THOR server on %s:%d - %s",
                             THOR_LISTEN_HOST, THOR_LISTEN_PORT, server_binding_error)
            raise

    async def _handle_individual_thor_client_connection(self,
                                                        reader: asyncio.StreamReader,
                                                        writer: asyncio.StreamWriter):
        thor_client_ip_address = writer.get_extra_info("peername")
        logging.info("THOR client connected from %s", thor_client_ip_address)
        try:
            while not self._shutdown_coordinator.is_shutdown_requested():
                raw_syslog_json = await reader.readline()
                if not raw_syslog_json:
                    logging.info("THOR client %s finished scanning and disconnected", thor_client_ip_address)
                    return
                await self._process_single_thor_message(raw_syslog_json, thor_client_ip_address)

        except Exception as connection_error:
            logging.error("THOR connection error from %s: %s", thor_client_ip_address, connection_error)
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _process_single_thor_message(self, raw_syslog_json: bytes, client_address) -> None:
        transformed_message = self._syslog_json_transformer.transform_thor_json_events(
            raw_syslog_json.rstrip(CRLF_BYTES)
        )
        if transformed_message is None:
            return
        try:
            await self._send_json_to_wazuh(transformed_message)
        except ConnectionError as wazuh_connection_error:
            logging.warning("Client %s - %s", client_address, wazuh_connection_error)
    async def shutdown_thor_server_completely(self) -> None:
        if self._thor_server:
            self._thor_server.close()
            await self._thor_server.wait_closed()

async def run_thor_json_service() -> None:
    logging_manager = LoggingManager()
    logging_manager.initialize_logging()
    shutdown_coordinator = ServiceShutdownCoordinator()
    json_transformer = SyslogJsonTransformer()
    wazuh_syslog_forwarder = WazuhSyslogForwarder(shutdown_coordinator)
    thor_connection_handler = ThorClientConnectionHandler(
        json_transformer,
        wazuh_syslog_forwarder.send_message_to_wazuh_server,
        shutdown_coordinator
    )
    await thor_connection_handler.start_thor_server_listening()

    def handle_shutdown() -> None:
        logging.info("Stoping THOR JSON Service received - stopping service safely")
        shutdown_coordinator.request_service_shutdown()
    event_loop = asyncio.get_running_loop()
    for shutdown_signal in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            event_loop.add_signal_handler(shutdown_signal, handle_shutdown)

    logging.info("THOR JSON Service ready - %s", datetime.now(timezone.utc).isoformat())
    await shutdown_coordinator.wait_for_shutdown_signal()
    logging.info("Shutdown initiated")
    await thor_connection_handler.shutdown_thor_server_completely()
    await wazuh_syslog_forwarder.shutdown_wazuh_forwarder_completely()
    logging.info("THOR JSON Service stopped safely")

if __name__ == "__main__":
    try:
        asyncio.run(run_thor_json_service())
    except Exception:
        logging.exception("Fatal service error")
        raise
