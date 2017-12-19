from typing import Tuple, Union
from abc import ABC, abstractclassmethod
from client.session import Session
from client.user import User


class OAuth2Db(ABC):
    @abstractclassmethod
    def __init__(self) -> None:
        pass

    @abstractclassmethod
    def get_session(self, session_id: str) -> Union[Tuple[Session, User], None]:
        pass

    @abstractclassmethod
    def save_session(self, session: Session, user: User) -> None:
        pass
