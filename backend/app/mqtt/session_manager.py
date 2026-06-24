# app/mqtt/session_manager.py

from collections import deque
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Dict, List, Optional


class MQTTSessionManager:
    """
    Central MQTT session manager.

    Tracks:
    - MQTT client instance
    - Connection status
    - Connection timestamps
    - Recent messages
    - Publish/receive statistics
    - Active subscriptions
    """

    def __init__(self, max_messages: int = 1000):
        self._lock = RLock()

        # Connection state
        self.connected: bool = False
        self.client = None
        self.connected_at: Optional[datetime] = None
        self.last_activity: Optional[datetime] = None

        # Statistics
        self.messages_received: int = 0
        self.messages_published: int = 0

        # Subscription tracking
        self.subscriptions: set[str] = set()

        # Recent messages buffer
        self.messages: deque = deque(maxlen=max_messages)

    # =====================================================
    # CONNECTION MANAGEMENT
    # =====================================================

    def set_client(self, client) -> None:
        """Store active MQTT client and mark session connected."""
        with self._lock:
            self.client = client
            self.connected = True
            now = datetime.now(timezone.utc)

            self.connected_at = now
            self.last_activity = now

    def disconnect(self) -> None:
        """Clear connection state."""
        with self._lock:
            self.client = None
            self.connected = False
            self.connected_at = None
            self.last_activity = None
            self.subscriptions.clear()

    def is_connected(self) -> bool:
        """Return current connection state."""
        with self._lock:
            return self.connected

    # =====================================================
    # MESSAGE MANAGEMENT
    # =====================================================

    def add_message(
        self,
        topic: str,
        payload: Any,
        qos: Optional[int] = None,
        retained: Optional[bool] = None,
    ) -> None:
        """Store incoming MQTT message."""
        with self._lock:
            now = datetime.now(timezone.utc)

            self.messages_received += 1
            self.last_activity = now

            self.messages.appendleft(
                {
                    "topic": topic,
                    "payload": payload,
                    "qos": qos,
                    "retained": retained,
                    "timestamp": now.isoformat(),
                }
            )

    def increment_published(self) -> None:
        """Increment publish counter."""
        with self._lock:
            self.messages_published += 1
            self.last_activity = datetime.now(timezone.utc)

    def get_messages(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return most recent messages."""
        with self._lock:
            return list(self.messages)[:limit]

    def clear_messages(self) -> None:
        """Remove all stored messages."""
        with self._lock:
            self.messages.clear()

    # =====================================================
    # SUBSCRIPTIONS
    # =====================================================

    def add_subscription(self, topic: str) -> None:
        with self._lock:
            self.subscriptions.add(topic)

    def remove_subscription(self, topic: str) -> None:
        with self._lock:
            self.subscriptions.discard(topic)

    def get_subscriptions(self) -> List[str]:
        with self._lock:
            return sorted(self.subscriptions)

    # =====================================================
    # STATUS / STATS
    # =====================================================

    def get_status(self) -> Dict[str, Any]:
        """Return current MQTT session status."""

        with self._lock:
            uptime_seconds = None

            if self.connected and self.connected_at:
                uptime_seconds = int(
                    (
                        datetime.now(timezone.utc)
                        - self.connected_at
                    ).total_seconds()
                )

            return {
                "connected": self.connected,
                "connected_at": (
                    self.connected_at.isoformat()
                    if self.connected_at
                    else None
                ),
                "last_activity": (
                    self.last_activity.isoformat()
                    if self.last_activity
                    else None
                ),
                "uptime_seconds": uptime_seconds,
                "messages_received": self.messages_received,
                "messages_published": self.messages_published,
                "subscriptions": len(self.subscriptions),
                "subscription_topics": sorted(
                    list(self.subscriptions)
                ),
                "stored_messages": len(self.messages),
            }

    # =====================================================
    # RESET
    # =====================================================

    def reset(self) -> None:
        """
        Fully reset session state.

        Safe because RLock allows nested locking.
        """
        with self._lock:
            self.disconnect()

            self.messages.clear()

            self.messages_received = 0
            self.messages_published = 0


# Singleton instance used across the application
mqtt_session = MQTTSessionManager()
