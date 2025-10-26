from rabbitmq import get_rabbitmq_connection_and_channel
from dotenv import load_dotenv

load_dotenv()

try:
    connection, channel = get_rabbitmq_connection_and_channel()

    channel.queue_declare(queue='hello')
    channel.basic_publish(
        exchange='',
        routing_key='hello',
        body='Hello from Python!'
    )
    print(" [x] Sent 'Hello from Python!'")

finally:
    try:
        if channel and channel.is_open:
            channel.close()
    except Exception as e:
        print(f"Error closing channel: {e}")

    try:
        if connection and connection.is_open:
            connection.close()
    except Exception as e:
        print(f"Error closing connection: {e}")
