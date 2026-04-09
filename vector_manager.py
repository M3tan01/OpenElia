#!/usr/bin/env python3
import os
import json
from datetime import datetime

class VectorManager:
    def __init__(self, db_path="state/vector_db"):
        self.db_path = db_path
        self._client = None
        self._collection = None

    @property
    def client(self):
        if self._client is None:
            import chromadb
            os.makedirs(self.db_path, exist_ok=True)
            self._client = chromadb.PersistentClient(path=self.db_path)
        return self._client

    @property
    def collection(self):
        if self._collection is None:
            self._collection = self.client.get_or_create_collection(name="engagement_memory")
        return self._collection

    def index_event(self, source, event_type, content, metadata=None):
        timestamp = datetime.utcnow().isoformat()
        event_id = f"{event_type}_{timestamp}_{os.urandom(4).hex()}"
        
        if metadata is None:
            metadata = {}
        
        metadata.update({
            "source": source,
            "type": event_type,
            "timestamp": timestamp
        })

        self.collection.add(
            documents=[content],
            metadatas=[metadata],
            ids=[event_id]
        )

    def search(self, query, limit=5):
        return self.collection.query(
            query_texts=[query],
            n_results=limit
        )

    def check_cache(self, prompt: str, threshold: float = 0.1):
        """
        Check if a highly similar prompt has been answered before.
        Returns the cached text or None.
        """
        try:
            results = self.collection.query(
                query_texts=[prompt],
                n_results=1,
                where={"type": "llm_cache"}
            )
            
            if results["documents"] and results["distances"]:
                distance = results["distances"][0][0]
                # ChromaDB distance: lower is more similar (0.0 is exact)
                if distance < threshold:
                    return results["documents"][0][0]
        except Exception as e:
            print(f"Cache lookup failed: {e}")
        return None

    def cache_response(self, prompt: str, response: str):
        self.index_event("cache_engine", "llm_cache", prompt, metadata={"response": response})
