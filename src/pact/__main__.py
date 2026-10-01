import os

import uvicorn

from .server import create_app


def main() -> None:
    uvicorn.run(create_app(), host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8787")))


if __name__ == "__main__":
    main()
