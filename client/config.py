import os
import json
from json.decoder import JSONDecodeError
from typing import Union


class Config(object):
    def __init__(self) -> None:
        self.discovered: dict = None
        self.dynamic_configuration: dict = None
        self.__client_id: str = ""
        self.__client_secret: str = ""
        self.__discovery_url: str = ""
        self.__verify_ssl_server: bool = True
        self.__dynamic_registration: bool = False
        self.__base_url: str = ""
        self.__app_name: str = "js-oauth2"
        self.__userinfo_endpoint = ""
        self.__load_config_file()

    def __load_config_file(self) -> None:
        if not os.path.exists('config.json'):
            return

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
                if "dynamic_registration" in local_config:
                    self.__dynamic_registration = local_config["dynamic_registration"]
                if "base_url" in local_config:
                    self.__base_url = local_config["base_url"]
                if "app_name" in local_config:
                    self.__app_name = local_config["app_name"]
                if "userinfo_endpoint" in local_config:
                    self.__userinfo_endpoint = local_config["userinfo_endpoint"]
            except JSONDecodeError as _:
                pass

    def __get_discovered(self, attr: str) -> Union[str, None]:
        if self.discovered is not None and attr in self.discovered:
            return self.discovered[attr]
        else:
            return None

    def __get_dynamic(self, attr: str) -> Union[str, None]:
        if self.dynamic_configuration is not None and attr in self.dynamic_configuration:
            return self.dynamic_configuration[attr]
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

    def get_userinfo_endpoint(self) -> str:
        ret = self.__get_discovered("userinfo_endpoint")
        if ret is None:
            return self.__userinfo_endpoint
        else:
            return ret

    def get_registration_endpoint(self) -> str:
        ret = self.__get_discovered("registration_endpoint")
        if ret is None:
            return ""
        else:
            return ret

    def get_base_url(self) -> str:
        return self.__base_url

    def get_app_name(self) -> str:
        return self.__app_name

    def dynamic_registration_enabled(self) -> bool:
        return self.__dynamic_registration

    def get_client_id(self) -> str:
        ret = self.__get_dynamic("client_id")
        if ret is None:
            return self.__client_id
        else:
            return ret

    def get_client_secret(self) -> str:
        ret = self.__get_dynamic("client_secret")
        if ret is None:
            return self.__client_secret
        else:
            return ret

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

    def get_redirect_uri(self) -> str:
        return self.get_base_url() + "/callback"

    def get_revocation_endpoint(self) -> str:
        ret = self.__get_discovered("revocation_endpoint")
        if ret is None:
            return ""
        else:
            return ret

    @staticmethod
    def get_scope() -> str:
        return "openid email profile"

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

    def set_dynamic_configuration(self, dynamic_configuration: dict):
        self.dynamic_configuration = dynamic_configuration

    def get_dynamic_configuration(self) -> dict:
        return self.dynamic_configuration
