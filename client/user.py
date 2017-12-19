from client.db_object import BaseDbObject


class User(BaseDbObject):
    def __init__(self, email: str=None, sub: str=None) -> None:
        self.__email: str = email
        self.__sub: str = sub

    def set_email(self, email: str) -> None:
        self.__email = email

    def set_sub(self, sub: str) -> None:
        self.__sub = sub

    def get_email(self) -> str:
        return self.__email

    def get_sub(self) -> str:
        return self.__sub
