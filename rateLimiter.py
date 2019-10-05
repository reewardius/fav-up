import time
class RateLimiter:
    """Rate limits an HTTP client that would make get() and post() calls.
    Calls are rate-limited by host.
    https://quentin.pradet.me/blog/how-do-you-rate-limit-calls-with-aiohttp.html
    This class is not thread-safe."""
    RATE = 50
    MAX_TOKENS = 50

    def __init__(self, client):
        self.client = client
        self.tokens = self.MAX_TOKENS
        self.updated_at = time.monotonic()

    async def get(self, *args, **kwargs):
        """The new method GET
        """
        await self.wait_for_token()
        return self.client.get(*args, **kwargs)

    async def wait_for_token(self):
        """Wait for token released
        """
        while self.tokens < 1:
            self.add_new_tokens()
            await asyncio.sleep(0.1)
        self.tokens -= 1

    def add_new_tokens(self):
        """Add new tokens
        """
        now = time.monotonic()
        time_since_update = now - self.updated_at
        new_tokens = time_since_update * self.RATE
        if new_tokens > 1:
            self.tokens = min(self.tokens + new_tokens, self.MAX_TOKENS)
            self.updated_at = now