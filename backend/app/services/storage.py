# 📁 services/storage.py

from threading import Lock
from typing import Dict, List


class InMemoryStorage:
    def __init__(self):
        self._collections: Dict[str, dict] = {}
        self._history: List[dict] = []
        self._lock = Lock()  # Thread-safe lock

    # -------------------------------
    # COLLECTION OPERATIONS
    # -------------------------------
    def add_collection(self, collection_id: str, data: dict):
        with self._lock:
            self._collections[collection_id] = data

    def get_collection(self, collection_id: str):
        return self._collections.get(collection_id)

    def all_collections(self):
        return list(self._collections.values())

    # -------------------------------
    # HISTORY OPERATIONS
    # -------------------------------
    def add_history(self, record: dict):
        with self._lock:
            self._history.append(record)

    def get_history(self):
        return list(self._history)


# Create a single shared storage instance
storage = InMemoryStorage()
