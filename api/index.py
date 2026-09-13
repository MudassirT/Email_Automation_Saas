"""
Vercel Serverless Function Entrypoint for AutoMail AI.
Exposes the FastAPI ASGI application for Vercel's Python runtime.
"""

import os
import sys
import shutil
from pathlib import Path

# Add project root directory to sys.path so 'email_service' is discoverable
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Vercel Serverless environment handling:
# AWS Lambda / Vercel filesystems are strictly read-only except for /tmp.
# Redirect AUTOMAIL_DATA_DIR to /tmp/automail_data and seed default partitions.
if os.getenv("VERCEL") or not os.getenv("AUTOMAIL_DATA_DIR"):
    if os.getenv("VERCEL"):
        tmp_data = Path("/tmp/automail_data")
        try:
            tmp_data.mkdir(parents=True, exist_ok=True)
            if not os.getenv("AUTOMAIL_DATA_DIR"):
                os.environ["AUTOMAIL_DATA_DIR"] = str(tmp_data)

            # Seed pre-configured state, users, and tenants if available in repository
            repo_data = ROOT_DIR / "email_service" / "data"
            if repo_data.exists():
                for item in repo_data.iterdir():
                    target = tmp_data / item.name
                    if not target.exists():
                        if item.is_dir():
                            shutil.copytree(item, target)
                        else:
                            shutil.copy2(item, target)
        except Exception as e:
            print(f"[Vercel Initialization Warning] /tmp setup note: {e}")

# Import the FastAPI application
from email_service.server import app

# Export for Vercel Python runtime
__all__ = ["app"]
