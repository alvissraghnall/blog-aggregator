import pika
import os
from urllib.parse import urlparse, unquote

def get_rabbitmq_connection_and_channel():
    url = os.environ.get("RABBITMQ_CONNECTION_URL")
    if not url:
        raise ValueError("RABBITMQ_CONNECTION_URL is not set")

    parsed = urlparse(url)

    username = unquote(parsed.username) if parsed.username else ""
    password = unquote(parsed.password) if parsed.password else ""
    host = parsed.hostname or "localhost"
    port = parsed.port or 5672
    vhost = unquote(parsed.path[1:]) if parsed.path and len(parsed.path) > 1 else "/"

    credentials = pika.PlainCredentials(username, password)

    connection_params = pika.ConnectionParameters(
        host=host,
        port=port,
        virtual_host=vhost,
        credentials=credentials,
    )

    connection = pika.BlockingConnection(connection_params)
    channel = connection.channel()

    return connection, channel
