from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.db import DB_PATH, init_db, list_users


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate Credora registry to multi-user ownership tables.")
    parser.add_argument("--show-users", action="store_true", help="Print users after migration.")
    args = parser.parse_args()

    init_db()
    print(f"Migrated Credora registry: {DB_PATH}")
    print("Existing model, scan, alert, drift, and integrity rows were assigned to the bootstrap admin if they had no owner.")
    if args.show_users:
        for user in list_users():
            print(f"- {user['id']}: {user['username']} ({user['role']})")


if __name__ == "__main__":
    main()
