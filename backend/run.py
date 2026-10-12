"""Start the ExfilTrace backend:  python run.py [--config config.json] [--host 127.0.0.1] [--port 5000]"""
import argparse
import logging

from app.api import create_app
from app.config import Config, ConfigError
from app.service import MonitoringService


def main():
    parser = argparse.ArgumentParser(description="ExfilTrace backend")
    parser.add_argument("--config", help="path to config.json")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    try:
        config = Config.load(args.config)
    except ConfigError as exc:
        raise SystemExit(f"Configuration error: {exc}")
    service = MonitoringService(config)
    app = create_app(service=service)   # starts monitoring
    host = args.host or config["api"]["host"]
    port = args.port or config["api"]["port"]
    try:
        app.run(host=host, port=port, threaded=True, use_reloader=False)
    finally:
        service.stop()   # clean shutdown: stops observers and the USB poller


if __name__ == "__main__":
    main()
