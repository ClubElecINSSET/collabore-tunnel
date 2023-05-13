"""collabore tunnel SSH server"""

import asyncio
import logging
import os
import random
import string
import sys
import time
from asyncio import AbstractEventLoop
from collections import deque
from os import path
from types import FrameType
from typing import AnyStr, Optional, Tuple
from _asyncio import Task

import asyncssh
from asyncssh import SSHKey, SSHServerConnection
from asyncssh.channel import (
    SSHUNIXChannel,
    SSHUNIXSession,
    SSHUNIXSessionFactory,
)
from asyncssh.listener import create_unix_forward_listener
from asyncssh.misc import MaybeAwait
from loguru import logger
from loguru._handler import Handler


unix_sockets_dir: str = os.getenv("UNIX_SOCKETS_DIRECTORY", "/tmp/collabore-tunnel")
server_hostname: str = os.getenv("SERVER_HOSTNAME", "tnl.clb.re")
config_dir: str = os.getenv("CONFIG_DIRECTORY", ".")
welcome_banner_file: str = os.getenv("WELCOME_BANNER_FILE", "./welcome_banner.txt")
rate_limit_count: int = int(os.getenv("RATE_LIMIT_COUNT", "5"))
rate_limit_interval: int = int(os.getenv("RATE_LIMIT_INTERVAL", "60"))
max_connections_per_ip: int = int(os.getenv("MAX_CONNECTIONS_PER_IP", "5"))
timeout: int = int(os.getenv("TIMEOUT", "120"))
ssh_server_host: str = os.getenv("SSH_SERVER_HOST", "0.0.0.0")
ssh_server_port: int = int(os.getenv("SSH_SERVER_PORT", "22"))
log_level: str = os.getenv("LOG_LEVEL", "INFO")
log_depth: int = int(os.getenv("LOG_DEPTH", "2"))


def read_welcome_banner() -> str:
    """Read the welcome banner from a file"""
    if not os.path.exists(welcome_banner_file):
        return welcome_banner
    with open(welcome_banner_file, "r", encoding="UTF-8") as file:
        return file.read()


welcome_banner: str = read_welcome_banner()


class RateLimiter:
    """Rate limiter handling class"""

    def __init__(self, max_requests: int, interval: int):
        """Init class"""
        self.max_requests: int = max_requests
        self.interval: int = interval
        self.timestamps: deque = deque()

    def is_rate_limited(self) -> bool:
        """Check if rate limited"""
        now: float = time.time()
        while self.timestamps and self.timestamps[0] < now - self.interval:
            self.timestamps.popleft()
        if len(self.timestamps) >= self.max_requests:
            return True
        self.timestamps.append(now)
        return False


class ConcurrentConnections:
    """Concurrent connection handling class"""

    def __init__(self):
        """Init class"""
        self.ip_connections: dict = {}

    def increment(self, ip_addr: str) -> None:
        """Increment the number of concurrent connections for an IP"""
        if ip_addr not in self.ip_connections:
            self.ip_connections[ip_addr] = 1
        else:
            self.ip_connections[ip_addr] += 1

    def decrement(self, ip_addr: str) -> None:
        """Decrement the number of concurrent connections for an IP"""
        self.ip_connections[ip_addr] -= 1

    def get(self, ip_addr: str) -> int:
        """Get the number of concurent connection for an IP"""
        return self.ip_connections.get(ip_addr, 0)


ip_address_connections = ConcurrentConnections()


def check_concurrent_connections(ip_addr: str) -> bool:
    """Checking for concurrent connections"""
    return ip_address_connections.get(ip_addr) >= max_connections_per_ip


class SSHServer(asyncssh.SSHServer):
    """SSH server protocol handler class"""

    rate_limiters: dict = {}

    def __init__(self):
        """Init class"""
        self.conn: SSHServerConnection
        self.socket_path: str
        self.ip_addr: str

    def check_rate_limit(self, ip_addr: str) -> bool:
        """Check if rate limited"""
        if ip_addr not in self.rate_limiters:
            self.rate_limiters[ip_addr] = RateLimiter(
                rate_limit_count, rate_limit_interval
            )
        return self.rate_limiters[ip_addr].is_rate_limited()

    def connection_made(self, conn: SSHServerConnection) -> None:
        """Called when a connection is made"""
        self.conn = conn
        self.ip_addr, _ = conn.get_extra_info("peername")

        if self.check_rate_limit(self.ip_addr):
            conn.set_extra_info(rate_limited=True)

        if check_concurrent_connections(self.ip_addr):
            conn.set_extra_info(connection_limited=True)

        ip_address_connections.increment(self.ip_addr)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when a connection is lost or closed"""
        if exc:
            logging.info("The connection has been terminated: %s", str(exc))
        try:
            os.remove(self.socket_path)
        except AttributeError:
            pass
        ip_address_connections.decrement(self.ip_addr)

    def begin_auth(self, username: str) -> MaybeAwait[bool]:
        """Authentication has been requested by the client"""
        return False

    def password_auth_supported(self) -> bool:
        """Return whether or not password authentication is supported"""
        return True

    def generate_socket_path(self) -> str:
        """Return the path of a socket whose name has been randomly generated"""
        socket_name = get_random_slug(16)
        self.socket_path = os.path.join(unix_sockets_dir, f"{socket_name}.sock")
        self.conn.set_extra_info(socket_name=socket_name)
        return self.socket_path

    def unix_server_requested(self, listen_path: str):
        """Handle a request to listen on a UNIX domain socket"""
        rewrite_path: str = self.generate_socket_path()

        async def tunnel_connection(
            session_factory: SSHUNIXSessionFactory[AnyStr],
        ) -> Tuple[SSHUNIXChannel[AnyStr], SSHUNIXSession[AnyStr]]:
            return await self.conn.create_unix_connection(session_factory, listen_path)

        try:
            return create_unix_forward_listener(
                self.conn, asyncio.get_event_loop(), tunnel_connection, rewrite_path
            )
        except OSError as create_unix_forward_listener_exception:
            logging.error(
                "An error occurred while creating the forward listener: %s",
                str(create_unix_forward_listener_exception),
            )


async def handle_ssh_client(process) -> None:
    """Function called every time a client connects to the SSH server"""
    socket_name: str = process.get_extra_info("socket_name")
    rate_limited: bool = process.get_extra_info("rate_limited")
    connection_limited: bool = process.get_extra_info("connection_limited")
    response: str = ""

    async def process_timeout(process):
        """Function to terminate the connection automatically
        after a specific period of time (in minutes)"""
        await asyncio.sleep(timeout * 60)
        response = (
            f"Timeout: you were automatically ejected after {timeout} minutes of use.\n"
        )
        process.stdout.write(response + "\n")
        process.logger.info(
            f"The user was automatically ejected after {timeout} minutes of use"
        )
        process.close()

    if not rate_limited:
        if not connection_limited:
            if not socket_name:
                response = "Usage: ssh -R /:host:port ssh.tunnel.collabore.fr\n"
                process.stdout.write(response + "\n")
                process.logger.info(
                    "The user was ejected because they did not connect in port forwarding mode"
                )
                process.exit(1)
                return
            no_tls: str = f"{socket_name}.{server_hostname}"
            tls: str = f"https://{socket_name}.{server_hostname}"
            response = f"{welcome_banner}\nYour local service has been exposed to the public\n\
Internet address: {no_tls}\nTLS termination: {tls}\n"
            process.stdout.write(response + "\n")
            process.logger.info(f"Exposed on {no_tls}")
            read_task: Task = asyncio.create_task(process.stdin.read())
            timeout_task: Task = asyncio.create_task(process_timeout(process))
            done, pending = await asyncio.wait(
                [read_task, timeout_task], return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                try:
                    await task
                except asyncssh.BreakReceived:
                    pass
            for task in pending:
                task.cancel()

            process.exit(0)
        else:
            response = (
                "Per-IP connection limit: too many connections running over this IP.\n"
            )
            process.stdout.write(response + "\n")
            process.logger.warning("Rejected connection due to per-IP connection limit")
            process.exit(1)
            return
    else:
        response = "Rate limited: please try later.\n"
        process.stdout.write(response + "\n")
        process.logger.warning("Rejected connection due to rate limit")
        process.exit(1)
        return


async def start_ssh_server() -> None:
    """Start the SSH server"""
    ssh_key_file: str = path.join(config_dir, "id_rsa_host")
    await asyncssh.create_server(
        SSHServer,
        host=ssh_server_host,
        port=ssh_server_port,
        server_host_keys=[ssh_key_file],
        process_factory=handle_ssh_client,
        agent_forwarding=False,
        allow_scp=False,
        keepalive_interval=30,
    )
    logging.info("SSH server started successfully.")


def check_unix_sockets_dir() -> None:
    """If the directory for UNIX sockets does not exist, it is created"""
    if not path.exists(unix_sockets_dir):
        os.mkdir(unix_sockets_dir)
        logging.warning(
            "The %s folder does not exist, it has been created.", unix_sockets_dir
        )
    else:
        logging.info("The %s folder exist.", unix_sockets_dir)


def generate_ssh_key() -> None:
    """If the SSH key of the server does not exist, it is generated"""
    ssh_host_key: str = path.join(config_dir, "id_rsa_host")
    logging.info("Loading the SSH key")
    if not path.exists(ssh_host_key):
        logging.warning(
            "The SSH key for the host was not found, generation in progress..."
        )
        key: SSHKey = asyncssh.generate_private_key("ssh-rsa")
        private_key: bytes = key.export_private_key()
        with open(ssh_host_key, "wb") as ssh_host_key_data:
            ssh_host_key_data.write(private_key)
        logging.info("The key was successfully created!")
    else:
        logging.info("SSH key has been found")


class InterceptHandler(logging.Handler):
    """Intercept logging call"""

    def emit(self, record):
        """Find caller from where originated the logged message"""
        frame: FrameType = logging.currentframe()
        depth: int = log_depth
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1
        logger.opt(exception=record.exc_info).log(log_level, record.getMessage())


def init_logging():
    """Init logging with a custom handler"""
    logging.root.handlers: Handler = [InterceptHandler()]
    logging.root.setLevel(log_level)
    fmt = "<green>[{time}]</green> <level>[{level}]</level> - <level>{message}</level>"
    logger.configure(handlers=[{"sink": sys.stdout, "serialize": False, "format": fmt}])


def get_random_slug(length) -> str:
    """Function that generates a random string of a defined size"""
    chars: str = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=length))


if __name__ == "__main__":
    init_logging()
    logging.info("Starting collabore tunnel SSH server...")
    os.umask(0o000)
    generate_ssh_key()
    logging.info("Checking for the existence of a folder for UNIX sockets...")
    check_unix_sockets_dir()
    loop: AbstractEventLoop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(start_ssh_server())
    except KeyboardInterrupt:
        pass
    except (OSError, asyncssh.Error) as ssh_server_startup_exception:
        logging.critical(
            "An error occurred while starting the SSH server: %s",
            str(ssh_server_startup_exception),
        )
        sys.exit()
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        sys.exit()
