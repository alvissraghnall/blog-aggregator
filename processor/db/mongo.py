import os
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

def get_mongo_collection():
    """
    Establishes a connection to MongoDB and returns the specified collection.
    """
    connection_url = os.environ.get("MONGO_CONNECTION_URL")
    db_name = os.environ.get("MONGO_DATABASE_NAME")
    collection_name = os.environ.get("MONGO_COLLECTION_NAME")

    if not all([connection_url, db_name, collection_name]):
        raise ValueError("MongoDB environment variables are not set correctly.")

    try:
        client = MongoClient(connection_url)
        # The ismaster command is cheap and does not require auth.
        client.admin.command('ismaster')
        db = client[db_name]
        collection = db[collection_name]
        print("Successfully connected to MongoDB.")
        return collection
    except ConnectionFailure as e:
        print(f"Error connecting to MongoDB: {e}")
        raise
