#  Pyrogram - Telegram MTProto API Client Library for Python
#  Copyright (C) 2017-present Dan <https://github.com/delivrance>
#
#  This file is part of Pyrogram.
#
#  Pyrogram is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Pyrogram is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with Pyrogram.  If not, see <http://www.gnu.org/licenses/>.

import asyncio
import bisect
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from hashlib import sha1
from io import BytesIO
from typing import Any, Dict, List, Optional, Set

import pyrogram
from pyrogram import raw
from pyrogram.connection import Connection
from pyrogram.crypto import mtproto
from pyrogram.errors import (
    AuthKeyDuplicated,
    BadMsgNotification,
    FloodPremiumWait,
    FloodWait,
    InternalServerError,
    RPCError,
    SecurityCheckMismatch,
    ServiceUnavailable,
    Unauthorized,
)
from pyrogram.raw.all import layer
from pyrogram.raw.core import FutureSalts, Int, MsgContainer, TLObject

from .internals import MsgFactory, MsgId

log = logging.getLogger(__name__)


class SessionState(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    STARTED = "started"
    STOPPING = "stopping"


@dataclass
class SessionConfig:
    START_TIMEOUT: float = 2.0
    WAIT_TIMEOUT: float = 15.0
    SLEEP_THRESHOLD: float = 10.0
    MAX_RETRIES: int = 10
    ACKS_THRESHOLD: int = 10
    PING_INTERVAL: float = 5.0
    STORED_MSG_IDS_MAX_SIZE: int = 2000
    MSG_ID_FUTURE_THRESHOLD: float = 30.0
    MSG_ID_PAST_THRESHOLD: float = 300.0
    RETRY_DELAY: float = 0.5
    PING_DISCONNECT_DELAY: int = 25


@dataclass
class TransportError:
    AUTH_KEY_NOT_FOUND = 404
    TRANSPORT_FLOOD = 429
    INVALID_DC = 444

    MESSAGES = {404: "auth key not found", 429: "transport flood", 444: "invalid DC"}


class Result:
    __slots__ = ("value", "event")

    def __init__(self):
        self.value: Any = None
        self.event: asyncio.Event = asyncio.Event()


class SessionError(Exception):
    pass


class SessionTimeoutError(SessionError):
    pass


class Session:
    def __init__(
        self,
        client: "pyrogram.Client",
        dc_id: int,
        auth_key: bytes,
        test_mode: bool,
        is_media: bool = False,
        is_cdn: bool = False,
        config: Optional[SessionConfig] = None,
    ):
        self.client = client
        self.dc_id = dc_id
        self.auth_key = auth_key
        self.test_mode = test_mode
        self.is_media = is_media
        self.is_cdn = is_cdn
        self.config = config or SessionConfig()

        self.connection: Optional[Connection] = None
        self._state = SessionState.STOPPED
        self._state_lock = asyncio.Lock()

        self.auth_key_id = sha1(auth_key).digest()[-8:]
        self.session_id = os.urandom(8)
        self.salt = 0

        self.msg_factory = MsgFactory()
        self.pending_acks: Set[int] = set()
        self.results: Dict[int, Result] = {}
        self.stored_msg_ids: List[int] = []

        self.ping_task: Optional[asyncio.Task] = None
        self.recv_task: Optional[asyncio.Task] = None
        self.ping_task_event = asyncio.Event()

        self.is_started = asyncio.Event()

    @property
    def state(self) -> SessionState:
        """Get current session state"""
        return self._state

    async def _set_state(self, new_state: SessionState) -> None:
        """Set session state thread-safely"""
        async with self._state_lock:
            old_state = self._state
            self._state = new_state
            log.debug(
                "Session state changed: %s -> %s", old_state.value, new_state.value
            )

    async def start(self) -> None:
        """Start the session with improved error handling and retry logic"""
        if self._state != SessionState.STOPPED:
            log.warning("Session already started or starting")
            return

        await self._set_state(SessionState.STARTING)

        try:
            await self._establish_connection()
            await self._set_state(SessionState.STARTED)
            self.is_started.set()
            log.info("Session started successfully")
        except Exception as e:
            await self._set_state(SessionState.STOPPED)
            log.error("Failed to start session: %s", e)
            raise

    async def _establish_connection(self) -> None:
        """Establish connection with retry logic for transient failures"""
        max_attempts = 3

        for attempt in range(max_attempts):
            try:
                await self._create_connection()
                await self._initialize_session()
                return
            except (AuthKeyDuplicated, Unauthorized) as e:
                log.error("Authentication error: %s", e)
                await self._cleanup_connection()
                raise
            except ConnectionError as e:
                log.warning(
                    "Connection error (attempt %d/%d): %s", attempt + 1, max_attempts, e
                )
                await self._cleanup_connection()
                if attempt == max_attempts - 1:
                    raise
                await asyncio.sleep(self.config.RETRY_DELAY * (attempt + 1))
            except Exception as e:
                log.error("Unexpected error during connection: %s", e)
                await self._cleanup_connection()
                raise

    async def _create_connection(self) -> None:
        """Create and establish network connection"""
        self.connection = self.client.connection_factory(
            dc_id=self.dc_id,
            test_mode=self.test_mode,
            ipv6=self.client.ipv6,
            proxy=self.client.proxy,
            media=self.is_media,
            protocol_factory=self.client.protocol_factory,
            loop=self.client.loop,
        )

        await self.connection.connect()
        self.recv_task = self.client.loop.create_task(self._recv_worker())

    async def _initialize_session(self) -> None:
        """Initialize session with ping and layer setup"""
        await self.send(
            raw.functions.Ping(ping_id=0), timeout=self.config.START_TIMEOUT
        )

        if not self.is_cdn:
            await self._initialize_layer()

        self.ping_task = self.client.loop.create_task(self._ping_worker())

        await self._call_connect_handler()

        self._log_session_info()

    async def _initialize_layer(self) -> None:
        """Initialize Telegram layer for non-CDN connections"""
        await self.send(
            raw.functions.InvokeWithLayer(
                layer=layer,
                query=raw.functions.InitConnection(
                    api_id=await self.client.storage.api_id(),
                    app_version=self.client.app_version,
                    device_model=self.client.device_model,
                    system_version=self.client.system_version,
                    system_lang_code=self.client.system_lang_code,
                    lang_pack=self.client.lang_pack,
                    lang_code=self.client.lang_code,
                    query=raw.functions.help.GetConfig(),
                    params=self.client.init_connection_params,
                ),
            ),
            timeout=self.config.START_TIMEOUT,
        )

    async def _call_connect_handler(self) -> None:
        """Safely call user-defined connect handler"""
        if not self.is_media and callable(self.client.connect_handler):
            try:
                await self.client.connect_handler(self.client)
            except Exception as e:
                log.exception("Error in connect handler: %s", e)

    def _log_session_info(self) -> None:
        """Log session initialization information"""
        log.info(
            "Session initialized: Pyrogram v%s (Layer %s)", pyrogram.__version__, layer
        )
        log.info("Device: %s - %s", self.client.device_model, self.client.app_version)
        log.info("System: %s (%s)", self.client.system_version, self.client.lang_code)

    async def stop(self) -> None:
        """Stop session with proper cleanup of all resources"""
        if self._state == SessionState.STOPPED:
            return

        await self._set_state(SessionState.STOPPING)

        try:
            await self._cleanup_session()
        finally:
            await self._set_state(SessionState.STOPPED)
            log.info("Session stopped")

    async def _cleanup_session(self) -> None:
        """Clean up all session resources including tasks and handlers"""
        self.is_started.clear()
        self.stored_msg_ids.clear()

        if self.ping_task:
            self.ping_task_event.set()
            try:
                await asyncio.wait_for(self.ping_task, timeout=5.0)
            except asyncio.TimeoutError:
                self.ping_task.cancel()
            self.ping_task_event.clear()

        await self._cleanup_connection()

        await self._call_disconnect_handler()

    async def _cleanup_connection(self) -> None:
        """Clean up connection and receive task resources"""
        if self.connection:
            await self.connection.close()

        if self.recv_task:
            try:
                await asyncio.wait_for(self.recv_task, timeout=5.0)
            except asyncio.TimeoutError:
                self.recv_task.cancel()

    async def _call_disconnect_handler(self) -> None:
        """Safely call user-defined disconnect handler"""
        if not self.is_media and callable(self.client.disconnect_handler):
            try:
                await self.client.disconnect_handler(self.client)
            except Exception as e:
                log.exception("Error in disconnect handler: %s", e)

    @asynccontextmanager
    async def _session_context(self):
        """Context manager for automatic session lifecycle management"""
        try:
            await self.start()
            yield self
        finally:
            await self.stop()

    async def restart(self) -> None:
        """Restart session by stopping and starting again"""
        log.info("Restarting session")
        await self.stop()
        await self.start()

    async def _validate_message_security(self, msg) -> None:
        """Validate message security constraints including time and duplicate checks"""
        if len(self.stored_msg_ids) > self.config.STORED_MSG_IDS_MAX_SIZE:
            del self.stored_msg_ids[: self.config.STORED_MSG_IDS_MAX_SIZE // 2]

        if not self.stored_msg_ids:
            return

        if msg.msg_id < self.stored_msg_ids[0]:
            raise SecurityCheckMismatch("Message ID is lower than all stored values")

        if msg.msg_id in self.stored_msg_ids:
            raise SecurityCheckMismatch("Duplicate message ID detected")

        time_diff = (msg.msg_id - MsgId()) / 2**32

        if time_diff > self.config.MSG_ID_FUTURE_THRESHOLD:
            raise SecurityCheckMismatch(
                f"Message ID is {time_diff:.1f}s in the future (max: {self.config.MSG_ID_FUTURE_THRESHOLD}s)"
            )

        if time_diff < -self.config.MSG_ID_PAST_THRESHOLD:
            raise SecurityCheckMismatch(
                f"Message ID is {abs(time_diff):.1f}s in the past (max: {self.config.MSG_ID_PAST_THRESHOLD}s)"
            )

    async def handle_packet(self, packet: bytes) -> None:
        """Handle incoming packet with decryption, validation and message processing"""
        try:
            data = await self._decrypt_packet(packet)
            messages = self._extract_messages(data)

            log.debug("Received %d message(s)", len(messages))

            for msg in messages:
                await self._process_message(msg)

            await self._send_acks_if_needed()

        except SecurityCheckMismatch as e:
            log.warning("Security check failed: %s", e)
            await self.connection.close()
        except Exception as e:
            log.error("Error handling packet: %s", e)
            self.client.loop.create_task(self.restart())

    async def _decrypt_packet(self, packet: bytes):
        """Decrypt incoming packet using MTProto encryption"""
        try:
            return await self.client.loop.run_in_executor(
                pyrogram.crypto_executor,
                mtproto.unpack,
                BytesIO(packet),
                self.session_id,
                self.auth_key,
                self.auth_key_id,
            )
        except ValueError as e:
            log.debug("Decryption failed: %s", e)
            raise

    def _extract_messages(self, data) -> List:
        """Extract individual messages from container or single message"""
        return data.body.messages if isinstance(data.body, MsgContainer) else [data]

    async def _process_message(self, msg) -> None:
        """Process individual message including acks, security validation and routing"""
        if msg.seq_no % 2 != 0:
            if msg.msg_id not in self.pending_acks:
                self.pending_acks.add(msg.msg_id)

        await self._validate_message_security(msg)
        bisect.insort(self.stored_msg_ids, msg.msg_id)

        if isinstance(
            msg.body, (raw.types.MsgDetailedInfo, raw.types.MsgNewDetailedInfo)
        ):
            self.pending_acks.add(msg.body.answer_msg_id)
            return

        if isinstance(msg.body, raw.types.NewSessionCreated):
            log.debug("New session created")
            return

        msg_id = self._extract_response_msg_id(msg.body)

        if msg_id and msg_id in self.results:
            self.results[msg_id].value = getattr(msg.body, "result", msg.body)
            self.results[msg_id].event.set()
        elif self.client:
            self.client.loop.create_task(self.client.handle_updates(msg.body))

    def _extract_response_msg_id(self, body) -> Optional[int]:
        """Extract message ID from response body for matching with pending requests"""
        if isinstance(body, (raw.types.BadMsgNotification, raw.types.BadServerSalt)):
            return body.bad_msg_id
        elif isinstance(body, (FutureSalts, raw.types.RpcResult)):
            return body.req_msg_id
        elif isinstance(body, raw.types.Pong):
            return body.msg_id
        return None

    async def _send_acks_if_needed(self) -> None:
        """Send acknowledgments if threshold is reached"""
        if len(self.pending_acks) >= self.config.ACKS_THRESHOLD:
            log.debug("Sending %d acknowledgments", len(self.pending_acks))

            try:
                await self.send(
                    raw.types.MsgsAck(msg_ids=list(self.pending_acks)), False
                )
                self.pending_acks.clear()
            except OSError as e:
                log.warning("Failed to send acks: %s", e)

    async def _ping_worker(self) -> None:
        """Background worker that sends periodic pings to keep connection alive"""
        log.info("Ping worker started")

        try:
            while self._state == SessionState.STARTED:
                try:
                    await asyncio.wait_for(
                        self.ping_task_event.wait(), self.config.PING_INTERVAL
                    )
                    break
                except asyncio.TimeoutError:
                    pass

                try:
                    await self.send(
                        raw.functions.PingDelayDisconnect(
                            ping_id=0,
                            disconnect_delay=self.config.PING_DISCONNECT_DELAY,
                        ),
                        wait_response=False,
                    )
                except OSError as e:
                    log.warning("Ping failed: %s", e)
                    self.client.loop.create_task(self.restart())
                    break
                except RPCError:
                    pass

        finally:
            log.info("Ping worker stopped")

    async def _recv_worker(self) -> None:
        """Network receive worker that handles incoming packets"""
        log.info("Network worker started")

        try:
            while self._state in (SessionState.STARTING, SessionState.STARTED):
                packet = await self.connection.recv()

                if packet is None or len(packet) == 4:
                    await self._handle_transport_error(packet)
                    break

                self.client.loop.create_task(self.handle_packet(packet))

        except Exception as e:
            log.error("Network worker error: %s", e)
        finally:
            log.info("Network worker stopped")

    async def _handle_transport_error(self, packet: Optional[bytes]) -> None:
        """Handle transport-level errors and trigger appropriate responses"""
        if packet:
            error_code = -Int.read(BytesIO(packet))
            error_msg = TransportError.MESSAGES.get(error_code, "unknown error")

            if error_code == TransportError.AUTH_KEY_NOT_FOUND:
                raise Unauthorized(
                    "Auth key not found. Delete session file and re-authenticate."
                )

            log.warning("Transport error: %s (%s)", error_code, error_msg)

        if self.is_started.is_set():
            self.client.loop.create_task(self.restart())

    async def send(
        self, data: TLObject, wait_response: bool = True, timeout: float = None
    ) -> Any:
        """Send data to Telegram servers with optional response waiting"""
        if timeout is None:
            timeout = self.config.WAIT_TIMEOUT

        message = self.msg_factory(data)
        msg_id = message.msg_id

        if wait_response:
            self.results[msg_id] = Result()

        log.debug("Sending: %s", message)

        payload = await self._encrypt_message(message)

        try:
            await self.connection.send(payload)
        except OSError:
            self.results.pop(msg_id, None)
            raise

        if not wait_response:
            return None

        try:
            await asyncio.wait_for(self.results[msg_id].event.wait(), timeout)
        except asyncio.TimeoutError:
            self.results.pop(msg_id, None)
            raise SessionTimeoutError(f"Request timed out after {timeout}s")

        result = self.results.pop(msg_id).value

        if result is None:
            raise SessionTimeoutError("No response received")

        return await self._process_response(result, data, wait_response, timeout)

    async def _encrypt_message(self, message):
        """Encrypt message for transmission using MTProto encryption"""
        return await self.client.loop.run_in_executor(
            pyrogram.crypto_executor,
            mtproto.pack,
            message,
            self.salt,
            self.session_id,
            self.auth_key,
            self.auth_key_id,
        )

    async def _process_response(self, result, original_data, wait_response, timeout):
        """Process response with error handling and salt updates"""
        if isinstance(result, raw.types.RpcError):
            data_for_error = (
                original_data.query
                if isinstance(
                    original_data,
                    (
                        raw.functions.InvokeWithoutUpdates,
                        raw.functions.InvokeWithTakeout,
                    ),
                )
                else original_data
            )
            RPCError.raise_it(result, type(data_for_error))

        if isinstance(result, raw.types.BadMsgNotification):
            log.warning("Bad message: %s", BadMsgNotification(result.error_code))

        if isinstance(result, raw.types.BadServerSalt):
            log.debug("Updating server salt")
            self.salt = result.new_server_salt
            return await self.send(original_data, wait_response, timeout)

        return result

    async def invoke(
        self,
        query: TLObject,
        retries: int = None,
        timeout: float = None,
        sleep_threshold: float = None,
    ) -> Any:
        """Invoke query with retry logic, flood wait handling and error recovery"""
        if retries is None:
            retries = self.config.MAX_RETRIES
        if timeout is None:
            timeout = self.config.WAIT_TIMEOUT
        if sleep_threshold is None:
            sleep_threshold = self.config.SLEEP_THRESHOLD

        try:
            await asyncio.wait_for(self.is_started.wait(), self.config.WAIT_TIMEOUT)
        except asyncio.TimeoutError:
            raise SessionTimeoutError("Session not ready")

        query_name = self._get_query_name(query)

        for attempt in range(retries + 1):
            try:
                return await self.send(query, timeout=timeout)

            except (FloodWait, FloodPremiumWait) as e:
                if e.value > sleep_threshold >= 0:
                    raise

                log.warning(
                    '[%s] Flood wait: %ds for "%s"',
                    self.client.name,
                    e.value,
                    query_name,
                )
                await asyncio.sleep(e.value)

            except (OSError, InternalServerError, ServiceUnavailable) as e:
                if attempt == retries:
                    raise

                log_func = log.warning if attempt < 2 else log.info
                log_func(
                    '[%s] Retry %d/%d for "%s": %s',
                    self.client.name,
                    attempt + 1,
                    retries,
                    query_name,
                    str(e) or repr(e),
                )

                await asyncio.sleep(self.config.RETRY_DELAY)

        raise SessionError(f"Max retries exceeded for {query_name}")

    def _get_query_name(self, query: TLObject) -> str:
        """Extract human-readable query name for logging purposes"""
        inner_query = (
            query.query
            if isinstance(
                query,
                (raw.functions.InvokeWithoutUpdates, raw.functions.InvokeWithTakeout),
            )
            else query
        )
        return ".".join(inner_query.QUALNAME.split(".")[1:])

    async def __aenter__(self):
        """Async context manager entry point (на всякий случай)"""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit point with cleanup (на всякий случай)"""
        await self.stop()
