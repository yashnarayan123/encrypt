"""Run the dashboard:  python3 -m dashboard [port]  ->  http://127.0.0.1:8077/ ."""
import sys

from dashboard.server import run

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8077
    run(port=port)
