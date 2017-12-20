# -*- coding: utf-8 -*-
from flask import Flask, jsonify, redirect, session, request, render_template
from client.client import Client, generate_random_string
from client.config import Config
from client.validator import JwtValidatorException, JwtValidator
from client.session import Session
from client.user import User
from client.db_interface import OAuth2Db
from db_impl.sqlite import OAuthSqlite
from urllib.error import HTTPError


def generic_error_handler(error_object, status_code):
    """
    :param error_object: Exception object
    :type error_object: Exception
    :param status_code: HTTP error code
    :type status_code: int
    :rtype: object
    """
    resp_dict = {
        "success": False,
        "message": error_object.__class__.__name__ + ": " + str(error_object),
        "status_code": status_code
    }
    response = jsonify(resp_dict)
    response.status_code = status_code
    return response


class AppBaseException(Exception):
    status_code = 500

    def __init__(self, message, status_code=None, payload=None):
        """
        :param message: Exception message
        :type message: str
        :param status_code: HTTP status code
        :type status_code: int
        :param payload: JSON detailed info
        :type payload: dict
        """
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        """
        :rtype: dict
        """
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv

    def __str__(self):
        return self.message


class BadRequest(AppBaseException):
    def __init__(self, message, status_code=400, payload=None):
        AppBaseException.__init__(self, message, status_code, payload)


class InternalServerError(AppBaseException):
    def __init__(self, message, status_code=500, payload=None):
        AppBaseException.__init__(self, message, status_code, payload)


app = Flask(__name__)


@app.errorhandler(AppBaseException)
def handle_invalid_usage(error):
    return generic_error_handler(error, error.status_code)


@app.errorhandler(JwtValidatorException)
def handle_invalid_jwt(error):
    resp_dict = {
        "success": False,
        "message": error.__class__.__name__ + ": " + str(error),
        "status_code": 500
    }
    response = jsonify(resp_dict)
    response.status_code = 500
    return response

@app.errorhandler(HTTPError)
def handle_invalid_http(error: HTTPError):
    resp_dict = {
        "success": False,
        "message": error.__class__.__name__ + ": " + str(error) if 0 == len(error.info()) else str(error.info()),
        "detail": "" if 0 == len(error.msg) else error.msg,
        "status_code": error.code
    }
    response = jsonify(resp_dict)
    response.status_code = 500
    return response


@app.route('/', methods=['GET'])
def index():
    user = None
    if 'session_id' in session:
        user_session = _db.get_session(session['session_id'])
        if isinstance(user_session, tuple):
            user = user_session[1]

    if user is None:
        login_url = _client.get_authn_req_url(
            session,
            request.args.get("acr", None),
            request.args.get("forceAuthN", False)
        )
        return redirect(login_url)
    else:
        return render_template('index.html', username=user.get_email(), provider=_config.get_authorization_endpoint())


@app.route('/callback', methods=['GET'])
def redirect_uri_handler():
    token_is_valid = False
    if 'state' not in session or session['state'] != request.args['state']:
        raise BadRequest('Missing or invalid state')

    if 'code' not in request.args:
        raise BadRequest('No code in response')

    try:
        token_data = _client.get_token(request.args['code'])
        if "error" in token_data:
            err_response = jsonify({
                "success": False,
                "message": token_data["error"],
                "detail": "" if "error_description" not in token_data else token_data["error_description"],
                "status_code": 500
            })
            err_response.status_code = 500
            return err_response
    except Exception as e:
        raise BadRequest('Could not fetch token(s): ' + str(e))
    session.pop('state', None)

    # Store in basic server session, since flask session use cookie for storage
    user_session = Session()

    if 'access_token' in token_data:
        user_session.set_access_token(token_data['access_token'])

    if _jwt_validator and 'id_token' in token_data:
        # validate JWS; signature, aud and iss.
        # Token type, access token, ref-token and JWT
        if 0 == len(_config.get_issuer()):
            raise BadRequest('Could not validate token: no issuer configured')

        try:
            _jwt_validator.validate(token_data['id_token'], _config.get_issuer(), _config.get_client_id())
            token_is_valid = True
        except JwtValidatorException as bs:
            raise BadRequest('Could not validate token: ' + str(bs))
        except Exception as ve:
            raise BadRequest('Unexpected exception: ' + str(ve))

        user_session.set_id_token(token_data['id_token'])

    if not token_is_valid:
        raise BadRequest('Forbidden', status_code=403)

    if 'refresh_token' in token_data:
        user_session.set_refresh_token(token_data['refresh_token'])

    user_info = _client.get_user_info(user_session.get_access_token())
    if "email" not in user_info:
        user = User(email=None, sub=user_info["sub"])
    else:
        user = User(email=user_info["email"], sub=user_info["sub"])
    user_session.set_user_sub(user.get_sub())
    _db.save_session(user_session, user)
    session['session_id'] = user_session.get_id()
    return redirect('/')


if __name__ == '__main__':
    _db: OAuth2Db = OAuthSqlite()
    _config: Config = Config()
    _client: Client = Client(_config, _db)
    _jwt_validator = JwtValidator(_config)

    # Flask session secret key
    app.secret_key = generate_random_string()

    # app.run(host='127.0.0.1', port=22222, threaded=True)
    app.run(debug=True)
