import os
from dotenv import load_dotenv
from pymongo import MongoClient
from pathlib import Path

load_dotenv(Path(__file__).resolve().parent / ".env")

uri = os.getenv("MONGODB_URI")

if not uri:
    raise ValueError("MONGODB_URI is missing from .env")

client = MongoClient(uri, serverSelectionTimeoutMS=10000)

try:
    client.admin.command("ping")
    print("SUCCESS: Connected to MongoDB Atlas!")
except Exception as error:
    print("Connection failed:", error)
finally:
    client.close()