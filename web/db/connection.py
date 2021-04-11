from gino import Gino

from .. import config

DATABASE = Gino()


async def init_connection():
    await DATABASE.set_bind(config.DATABASE_URL.get_secret_value())


async def close_connection():
    await DATABASE.pop_bind().close()
