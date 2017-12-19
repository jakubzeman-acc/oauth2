from client.client import generate_random_string
from client.db_object import BaseDbObject
from client.client import dict_key_to_camel_case


class Session(BaseDbObject):
    def __init__(self, session_detail: dict=None) -> None:
        self.__access_token: str = None
        self.__refresh_token: str = None
        self.__id_token: str = None
        self.__user_sub: str = None

        if session_detail is None:
            self.__id: str = generate_random_string()
        else:
            if dict_key_to_camel_case("__id") in session_detail:
                self.__id: str = session_detail[dict_key_to_camel_case("__id")]
            if dict_key_to_camel_case("__access_token") in session_detail:
                self.__access_token = session_detail[dict_key_to_camel_case("__access_token")]
            if dict_key_to_camel_case("__refresh_token") in session_detail:
                self.__refresh_token = session_detail[dict_key_to_camel_case("__refresh_token")]
            if dict_key_to_camel_case("__id_token") in session_detail:
                self.__id_token = session_detail[dict_key_to_camel_case("__id_token")]
            if dict_key_to_camel_case("__user_sub") in session_detail:
                self.__user_sub = session_detail[dict_key_to_camel_case("__user_sub")]

    def set_access_token(self, access_token: str) -> None:
        self.__access_token = access_token

    def set_refresh_token(self, refresh_token: str) -> None:
        self.__refresh_token = refresh_token

    def set_id_token(self, id_token: str) -> None:
        self.__id_token = id_token

    def set_user_sub(self, user_sub: str) -> None:
        self.__user_sub = user_sub

    def get_id(self) -> str:
        return self.__id

    def get_access_token(self) -> str:
        return self.__access_token

    def get_refresh_token(self) -> str:
        return self.__refresh_token

    def get_id_token(self) -> str:
        return self.__id_token

    def get_user_sub(self) -> str:
        return self.__user_sub
