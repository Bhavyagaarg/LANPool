"""Await thread I/O before closing resources, including during cancellation."""
import asyncio
import anyio
from starlette.responses import StreamingResponse


async def disk_call(function, *args, **kwargs):
    work = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(work)
    except asyncio.CancelledError:
        with anyio.CancelScope(shield=True):
            await work
        raise


async def acquire_resource(acquire, release):
    work = asyncio.create_task(asyncio.to_thread(acquire))
    try:
        return await asyncio.shield(work)
    except asyncio.CancelledError:
        with anyio.CancelScope(shield=True):
            resource = await work
            await asyncio.to_thread(release, resource)
        raise


class ManagedStreamingResponse(StreamingResponse):
    """Release resources even if the connection fails before the first yield."""
    def __init__(self, *args, on_close, **kwargs):
        super().__init__(*args, **kwargs)
        self.on_close = on_close

    async def __call__(self, scope, receive, send):
        async def finish():
            try:
                if hasattr(self.body_iterator, "aclose"):
                    await self.body_iterator.aclose()
            finally:
                await self.on_close()
        try:
            await super().__call__(scope, receive, send)
        finally:
            with anyio.CancelScope(shield=True):
                cleanup = asyncio.create_task(finish())
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    await cleanup
                    raise
