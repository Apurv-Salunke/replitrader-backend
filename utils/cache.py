import redis
import os
import json
from typing import Any, Optional

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))

# Initialize Redis client
try:
    redis_client = redis.StrictRedis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        decode_responses=True  # Decode responses to strings
    )
    redis_client.ping() # Check connection
    print(f"Successfully connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
except redis.exceptions.ConnectionError as e:
    print(f"Error connecting to Redis: {e}")
    redis_client = None # Set client to None if connection fails

def set_cache(key: str, value: Any, ttl: Optional[int] = 3600) -> bool:
    """Sets a value in the Redis cache with an optional TTL (in seconds)."""
    if redis_client is None:
        print("Redis client not available.")
        return False
    try:
        serialized_value = json.dumps(value)
        if ttl:
            return redis_client.setex(key, ttl, serialized_value)
        else:
            return redis_client.set(key, serialized_value)
    except redis.exceptions.RedisError as e:
        print(f"Error setting cache key '{key}': {e}")
        return False
    except TypeError as e:
        print(f"Error serializing value for key '{key}': {e}")
        return False

def get_cache(key: str) -> Any:
    """Gets a value from the Redis cache."""
    if redis_client is None:
        print("Redis client not available.")
        return None
    try:
        cached_value = redis_client.get(key)
        if cached_value:
            return json.loads(cached_value)
        return None
    except redis.exceptions.RedisError as e:
        print(f"Error getting cache key '{key}': {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error deserializing value for key '{key}': {e}")
        # Attempt to return raw value if deserialization fails
        return cached_value

def delete_cache(key: str) -> bool:
    """Deletes a key from the Redis cache."""
    if redis_client is None:
        print("Redis client not available.")
        return False
    try:
        return redis_client.delete(key) > 0
    except redis.exceptions.RedisError as e:
        print(f"Error deleting cache key '{key}': {e}")
        return False

def clear_cache() -> bool:
    """Clears the entire Redis cache (use with caution)."""
    if redis_client is None:
        print("Redis client not available.")
        return False
    try:
        return redis_client.flushdb()
    except redis.exceptions.RedisError as e:
        print(f"Error flushing Redis DB: {e}")
        return False 