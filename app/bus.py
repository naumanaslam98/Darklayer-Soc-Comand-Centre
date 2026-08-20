import asyncio


class BroadcastBus:
    """Small in-process broadcast bus for live dashboard streams.

    This is intentionally bounded: slow browser clients drop old stream items
    rather than back-pressuring the ingestion/detection pipeline.
    """

    def __init__(self, maxsize: int = 500):
        self.clients: set[asyncio.Queue] = set()
        self.maxsize = maxsize

    async def publish(self, item: dict):
        dead = []
        for q in list(self.clients):
            try:
                if q.full():
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                q.put_nowait(item)
            except Exception:
                dead.append(q)
        for q in dead:
            self.clients.discard(q)

    def subscribe(self):
        q = asyncio.Queue(maxsize=self.maxsize)
        self.clients.add(q)
        return q

    def unsubscribe(self, q):
        self.clients.discard(q)


alert_bus = BroadcastBus(maxsize=200)
event_bus = BroadcastBus(maxsize=1000)
