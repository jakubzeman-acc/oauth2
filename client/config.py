import os
import json
from json.decoder import JSONDecodeError
from typing import Union


class Config(object):
    def __init__(self) -> None:
        self.discovered: dict = None
        self.__client_id: str = ""
        self.__client_secret: str = ""
        self.__discovery_url = ""
        self.__verify_ssl_server = True
        if os.path.exists('config.json'):
            with open('config.json') as fp:
                try:
                    local_config = json.load(fp)
                    if "client_id" in local_config:
                        self.__client_id = local_config["client_id"]
                    if "client_secret" in local_config:
                        self.__client_secret = local_config["client_secret"]
                    if "discovery_url" in local_config:
                        self.__discovery_url = local_config["discovery_url"]
                    if "verify_ssl_server" in local_config:
                        self.__verify_ssl_server = local_config["verify_ssl_server"]
                except JSONDecodeError as _:
                    pass

    def __get_discovered(self, attr: str) -> Union[str, None]:
        if self.discovered is not None and attr in self.discovered:
            return self.discovered[attr]
        else:
            return None

    def get_api_endpoint(self) -> str:
        ret = self.__get_discovered("api_endpoint")
        if ret is None:
            return ""
        else:
            return ret

    def get_authn_parameters(self) -> str:
        ret = self.__get_discovered("authn_parameters")
        if ret is None:
            return ""
        else:
            return ret

    def get_authorization_endpoint(self) -> str:
        ret = self.__get_discovered("authorization_endpoint")
        if ret is None:
            return ""
        else:
            return ret

    def get_base_url(self) -> str:
        ret = self.__get_discovered("base_url")
        if ret is None:
            return ""
        else:
            return ret

    def get_client_id(self) -> str:
        return self.__client_id

    def get_client_secret(self) -> str:
        return self.__client_secret

    @staticmethod
    def debug_enabled() -> bool:
        return True

    @staticmethod
    def disable_https() -> bool:
        return False

    def get_issuer(self) -> str:
        ret = self.__get_discovered("issuer")
        if ret is None:
            return ""
        else:
            return ret

    def get_jwks_uri(self) -> str:
        ret = self.__get_discovered("jwks_uri")
        if ret is None:
            return ""
        else:
            return ret

    def get_logout_endpoint(self) -> str:
        ret = self.__get_discovered("logout_endpoint")
        if ret is None:
            return ""
        else:
            return ret

    @staticmethod
    def get_redirect_uri() -> str:
        return "http://localhost:5000/callback"

    def get_revocation_endpoint(self) -> str:
        ret = self.__get_discovered("revocation_endpoint")
        if ret is None:
            return ""
        else:
            return ret

    @staticmethod
    def get_scope() -> str:
        return "openid"

    def get_token_endpoint(self) -> str:
        ret = self.__get_discovered("token_endpoint")
        if ret is None:
            return ""
        else:
            return ret

    def verify_ssl_server(self) -> bool:
        return self.__verify_ssl_server

    def set_discovery_content(self, dicsovered: dict):
        self.discovered = dicsovered

    def get_discovery_url(self) -> str:
        return self.__discovery_url
