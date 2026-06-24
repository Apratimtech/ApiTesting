import asyncio
import ssl
from datetime import datetime
import asyncio_mqtt
import traceback  # Added for better error debugging


class MQTTClientManager:
    def __init__(self):
        self.client = None
        self.connected = False
        self.broker_host = None
        self.broker_port = None
        self.client_id = None
        self.subscriptions = []
        self.messages = []          # Store received messages
        self.logs = []
        self.connected_at = None
        self._listener_task = None  # Background listener task

    async def _message_listener(self):
        """Background task to listen for incoming MQTT messages"""
        try:
            async with self.client.messages() as messages:
                async for message in messages:
                    try:
                        payload = message.payload.decode('utf-8') if isinstance(message.payload, bytes) else str(message.payload)

                        msg_data = {
                            "topic": message.topic,
                            "payload": payload,
                            "qos": message.qos,
                            "timestamp": datetime.utcnow().isoformat(),
                        }

                        self.messages.append(msg_data)

                        # Keep only last 500 messages to prevent memory bloat
                        if len(self.messages) > 500:
                            self.messages.pop(0)

                        self.logs.append({
                            "timestamp": datetime.utcnow().isoformat(),
                            "event": "IN",
                            "message": f"Received on {message.topic}"
                        })
                    except Exception as e:
                        self.logs.append({
                            "timestamp": datetime.utcnow().isoformat(),
                            "event": "ERROR",
                            "message": f"Message processing error: {str(e)}"
                        })
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logs.append({
                "timestamp": datetime.utcnow().isoformat(),
                "event": "ERROR",
                "message": f"Listener error: {str(e)}"
            })

    async def connect(
        self,
        broker_host,
        broker_port,
        username=None,
        password=None,
        client_id=None,
        tls_enabled=False,
        tls_insecure=False,
        keepalive=60,
    ):
        try:
            tls_context = None
            if tls_enabled:
                tls_context = ssl.create_default_context()
                if tls_insecure:
                    tls_context.check_hostname = False
                    tls_context.verify_mode = ssl.CERT_NONE

            # === DEBUG PRINTS ===
            print("=" * 80)
            print("HOST =", broker_host)
            print("PORT =", broker_port)
            print("TLS =", tls_enabled)
            print("USERNAME =", username)
            print("CLIENT_ID =", client_id)
            print("=" * 80)

            self.client = asyncio_mqtt.Client(
                hostname=broker_host,
                port=broker_port,
                username=username or None,
                password=password or None,
                client_id=client_id,
                keepalive=keepalive,
                tls_context=tls_context,
            )

            await self.client.__aenter__()
            self.connected = True
            self.connected_at = datetime.utcnow()
            self.broker_host = broker_host
            self.broker_port = broker_port
            self.client_id = client_id

            # Start message listener
            if self._listener_task:
                self._listener_task.cancel()
            self._listener_task = asyncio.create_task(self._message_listener())

            self.logs.append({
                "timestamp": datetime.utcnow().isoformat(),
                "event": "CONNECT",
                "message": f"Connected to {broker_host}:{broker_port}"
            })

            return {
                "success": True,
                "client_id": client_id,
            }
        except Exception as e:
            import traceback
            traceback.print_exc()

            self.logs.append({
                "timestamp": datetime.utcnow().isoformat(),
                "event": "ERROR",
                "message": str(e)
            })
            return {
                "success": False,
                "message": str(e)
            }

    async def publish(
        self,
        topic,
        payload,
        qos=0,
        retain=False,
    ):
        if not self.connected or not self.client:
            return {
                "success": False,
                "message": "MQTT not connected"
            }
        try:
            await self.client.publish(
                topic,
                str(payload),
                qos=qos,
                retain=retain,
            )
            self.logs.append({
                "timestamp": datetime.utcnow().isoformat(),
                "event": "PUBLISH",
                "message": f"Published to {topic}"
            })
            return {
                "success": True,
                "message_id": int(datetime.utcnow().timestamp())
            }
        except Exception as e:
            traceback.print_exc()
            return {
                "success": False,
                "message": str(e)
            }

    async def subscribe(
        self,
        topic,
        qos=0,
    ):
        if not self.connected or not self.client:
            raise Exception("MQTT not connected")

        await self.client.subscribe(topic, qos=qos)

        if topic not in self.subscriptions:
            self.subscriptions.append(topic)

        self.logs.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event": "SUBSCRIBE",
            "message": topic
        })
        return {
            "success": True
        }

    async def unsubscribe(
        self,
        topic,
    ):
        if not self.connected or not self.client:
            raise Exception("MQTT not connected")

        await self.client.unsubscribe(topic)

        if topic in self.subscriptions:
            self.subscriptions.remove(topic)

        self.logs.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event": "UNSUBSCRIBE",
            "message": topic
        })
        return {
            "success": True
        }

    def get_status(self):
        uptime = 0
        if self.connected and self.connected_at:
            uptime = int(
                (datetime.utcnow() - self.connected_at).total_seconds()
            )
        return {
            "connected": self.connected,
            "broker_host": self.broker_host,
            "broker_port": self.broker_port,
            "client_id": self.client_id,
            "subscriptions": self.subscriptions,
            "uptime_seconds": uptime,
        }

    def get_messages(self):
        """Return a copy of messages to prevent modification issues"""
        return self.messages.copy()

    def get_logs(self):
        return self.logs.copy()

    async def disconnect(self):
        try:
            # Cancel listener task
            if self._listener_task:
                self._listener_task.cancel()
                try:
                    await self._listener_task
                except asyncio.CancelledError:
                    pass
                self._listener_task = None

            if self.client:
                await self.client.__aexit__(None, None, None)

            self.connected = False
            self.logs.append({
                "timestamp": datetime.utcnow().isoformat(),
                "event": "DISCONNECT",
                "message": "Disconnected"
            })
            return {
                "success": True
            }
        except Exception as e:
            traceback.print_exc()
            return {
                "success": False,
                "message": str(e)
            }
