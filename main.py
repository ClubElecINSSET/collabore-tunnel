"""collabore tunnel SSH server"""

import asyncio
import logging
import os
import random
import string
import sys
from asyncio import AbstractEventLoop
from os import path
from types import FrameType
from typing import AnyStr, Optional, Tuple

import asyncssh
from asyncssh import SSHKey, SSHServerConnection
from asyncssh.listener import create_unix_forward_listener
from asyncssh.misc import MaybeAwait
from asyncssh.channel import SSHUNIXChannel, SSHUNIXSession, SSHUNIXSessionFactory
from loguru import logger
from loguru._handler import Handler

unix_sockets_dir: str = os.getenv("UNIX_SOCKETS_DIRECTORY", "/tmp/collabore-tunnel")
server_hostname: str = os.getenv("SERVER_HOSTNAME", "tnl.clb.re")
config_dir: str = os.getenv("CONFIG_DIRECTORY", ".")
ssh_server_host: str = os.getenv("SSH_SERVER_HOST", "0.0.0.0")
ssh_server_port: int = int(os.getenv("SSH_SERVER_PORT", "22"))
log_level: str = os.getenv("LOG_LEVEL", "INFO")
log_depth: int = int(os.getenv("LOG_DEPTH", "2"))

welcome_banner = f"===============================================================================\n\
Welcome to collabore tunnel!\n\
collabore tunnel is a free and open source service offered as part of the\n\
club elec collabore platform (https://collabore.fr) operated by club elec that\n\
allows you to expose your local services on the public Internet.\n\
To learn more about collabore tunnel,\n\
visit the documentation website: https://tunnel.collabore.fr/\n\
club elec (https://clubelec.insset.fr) is a french not-for-profit\n\
student organisation.\n\
===============================================================================\n\n"


class SSHServer(asyncssh.SSHServer):
    """SSH server protocol handler class"""

    def __init__(self):
        """Init class"""
        self.conn: SSHServerConnection
        self.socket_path: str

    def connection_made(self, conn: SSHServerConnection) -> None:
        """Called when a connection is made"""
        self.conn = conn

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when a connection is lost or closed"""
        if exc:
            logging.info("The connection has been terminated: %s", str(exc))
        try:
            os.remove(self.socket_path)
        except AttributeError:
            pass

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
    response: str = ""
    if not socket_name:
        response = f"Usage: ssh -R /:host:port ssh.tunnel.collabore.fr\n"
        process.stdout.write(response + "\n")
        process.exit(1)
        logging.info(
            "The user was ejected because they did not connect in port forwarding mode."
        )
        return
    no_tls: str = f"{socket_name}.{server_hostname}"
    tls: str = f"https://{socket_name}.{server_hostname}"
    response = f"{welcome_banner}Your local service has been exposed\
 to the public Internet address: {no_tls}\nTLS termination: {tls}\n"
    process.stdout.write(response + "\n")
    logging.info(f"Exposed on {no_tls}, {tls}.")
    while not process.stdin.at_eof():
        try:
            await process.stdin.read()
        except asyncssh.TerminalSizeChanged:
            pass
    process.exit(0)


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
    for name in logging.root.manager.loggerDict.keys():
        logging.getLogger(name).handlers: list = []
        logging.getLogger(name).propagate: bool = True
    logger.configure(handlers=[{"sink": sys.stdout, "serialize": False}])


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
