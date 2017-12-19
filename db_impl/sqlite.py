import os
import json
from client.db_interface import OAuth2Db
from sqlite3 import connect
from client.session import Session
from client.user import User
from typing import Tuple, Union


class OAuthSqlite(OAuth2Db):
    def __init__(self, db_path: str = "oauth2.db"):
        super().__init__()
        self.__db_path: str = db_path
        if not os.path.exists(self.__db_path):
            self.__create_db()

    def __create_db(self):
        with connect(self.__db_path) as db:
            c = db.cursor()
            c.execute("CREATE TABLE user (sub text PRIMARY KEY ASC, email text)")
            c.execute("CREATE TABLE session (id text PRIMARY KEY ASC, detail text)")

    def get_session(self, session_id: str) -> Union[Tuple[Session, User], None]:
        with connect(self.__db_path) as db:
            c = db.cursor()
            session_row = c.execute("SELECT detail FROM session WHERE id = ?", (session_id,)).fetchone()
            if 0 == len(session_row):
                return None
            else:
                session = Session(session_detail=json.loads(session_row[0]))
                user_row = c.execute("SELECT email FROM user WHERE sub = ?", (session.get_user_sub(),)).fetchone()
                if 0 == len(user_row):
                    return None
                user = User(sub=session.get_user_sub(), email=user_row[0])
                return session, user

    @staticmethod
    def __insert_update_user(db, sub: str, email: str):
        c = db.cursor()
        user_row = c.execute("SELECT email FROM user WHERE sub = ?", (sub,)).fetchone()
        if 0 == len(user_row):
            c.execute("INSERT INTO user VALUES (?, ?)", (sub, email))
        else:
            c.execute("UPDATE user set email = ? WHERE sub = ?", (email, sub))

    def save_session(self, session: Session, user: User) -> None:
        with connect(self.__db_path) as db:
            c = db.cursor()
            OAuthSqlite.__insert_update_user(db, user.get_sub(), user.get_email())
            c.execute("INSERT INTO session VALUES (?, ?)", (session.get_id(), str(session)))
