import asyncio
import subprocess
import time
from xssam.cli import main as cli_main
import sys

async def test_xssam():
    # 1. Start the vulnerable app in the background
    process = subprocess.Popen(["python", "tests/vulnerable_app/app.py"])
    time.sleep(2) # Wait for flask to start

    try:
        # Mock sys.argv to simulate CLI call
        sys.argv = ["xssam", "-u", "http://127.0.0.1:5000", "--authorized", "--depth", "2"]
        cli_main()
    finally:
        process.terminate()

if __name__ == "__main__":
    asyncio.run(test_xssam())
