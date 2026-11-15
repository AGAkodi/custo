"""Insert the small, fictional foundation graph."""
import asyncio

from app.config import get_settings
from app.memory import retrieve_context, seed_foundation


async def main() -> None:
    settings = get_settings()
    await seed_foundation(settings)
    print(await retrieve_context(settings, "Foundation incident"))


if __name__ == "__main__":
    asyncio.run(main())
