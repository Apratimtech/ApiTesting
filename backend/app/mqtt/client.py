import asyncio_mqtt


class MQTTClientManager:

    def __init__(self):
        self.client = None

    async def connect(
        self,
        broker,
        port,
        username=None,
        password=None,
        client_id=None
    ):

        self.client = asyncio_mqtt.Client(
            hostname=broker,
            port=port,
            username=username,
            password=password,
            client_id=client_id
        )

        await self.client.__aenter__()

        return True

    async def publish(
        self,
        topic,
        payload,
        qos=0,
        retain=False
    ):

        await self.client.publish(
            topic,
            str(payload),
            qos=qos,
            retain=retain
        )

    async def disconnect(self):

        if self.client:
            await self.client.__aexit__(
                None,
                None,
                None
            )
