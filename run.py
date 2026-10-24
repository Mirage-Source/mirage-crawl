"""Entrypoint: python run.py"""

import asyncio
import signal

from mirage_crawl.config import Config
from mirage_crawl.server import build_app, start_sites


async def main() -> None:
    config = Config.from_env()
    app = build_app(config)
    runner = await start_sites(app, config)
    sensor = app["sensor"]

    print(f"mirage-crawl {config.sensor_id}")
    print(f"  public      {sensor.public_address[0]}:{sensor.public_address[1]}")
    if config.front_socket:
        print(f"  tls front   {config.front_socket}  (trusts X-Forwarded-For + JA4)")
    if config.admin_socket:
        print(f"  admin       {config.admin_socket}  (/healthz)")
    if sensor.proxy_address:
        print(f"  proxy       {sensor.proxy_address[0]}:{sensor.proxy_address[1]}"
              f"  (trusts {config.trust_proxy_header}; header order is the proxy's)")
    print(f"  origin      {config.origin}")
    print(f"  events      {config.log_dir}")
    print(f"  ranges      {config.ranges_file}")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    try:
        await stop.wait()
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
