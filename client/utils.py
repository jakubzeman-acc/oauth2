import random
import string
from ssl import create_default_context, SSLContext
from _ssl import CERT_NONE
from client.config import Config


def generate_random_string() -> str:
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))


def get_ssl_context(config: Config) -> SSLContext:
    ctx = create_default_context()

    if not config.verify_ssl_server():
        print('Not verifying ssl certificates')
        ctx.check_hostname = False
        ctx.verify_mode = CERT_NONE
    return ctx


def dict_key_to_camel_case(key: str) -> str:
    if key.startswith("__"):
        key = key[2:]
    ret = ''.join(x for x in key.title() if "_" != x)
    return ret[0].lower() + ret[1:]
