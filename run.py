"""Entrypoint: python run.py"""

from aiohttp import web

from mirage_crawl.config import Config
from mirage_crawl.server import build_app


def main() -> None:
    config = Config.from_env()
    app = build_app(config)
    print(f"mirage-crawl {config.sensor_id} on {config.host}:{config.port}")
    print(f"  origin      {config.origin}")
    print(f"  events      {config.log_dir}")
    print(f"  ranges      {config.ranges_file}")
    web.run_app(app, host=config.host, port=config.port, access_log=None)


if __name__ == "__main__":
    main()
