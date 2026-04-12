"""TCP drain server -- destination of the victim's LocalForward."""

import asyncio

PORT = 6379


async def handle(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    srv = await asyncio.start_server(handle, "0.0.0.0", PORT)
    print(f"drain server listening on :{PORT}", flush=True)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
