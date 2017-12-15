# -*- coding: utf-8 -*-
from flask import Flask, jsonify, redirect, session, request
from client.client import Client, generate_random_string
from client.config import Config
from client.validator import JwtValidatorException, JwtValidator
from jwkest import BadSignature


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


class UserSession(object):
    def __init__(self):
        pass

    access_token = None
    refresh_token = None
    id_token = None
    access_token_json = None
    id_token_json = None
    name = None
    api_response = None


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


@app.route('/', methods=['GET'])
def index():
    login_url = _client.get_authn_req_url(session, request.args.get("acr", None), request.args.get("forceAuthN", False))
    return redirect(login_url)


@app.route('/callback', methods=['GET'])
def redirect_uri_handler():
    if 'state' not in session or session['state'] != request.args['state']:
        raise BadRequest('Missing or invalid state')

    if 'code' not in request.args:
        raise BadRequest('No code in response')

    try:
        token_data = _client.get_token(request.args['code'])
    except Exception as e:
        raise BadRequest('Could not fetch token(s): ' + str(e))
    session.pop('state', None)

    # Store in basic server session, since flask session use cookie for storage
    user = UserSession()

    if 'access_token' in token_data:
        user.access_token = token_data['access_token']

    if _jwt_validator and 'id_token' in token_data:
        # validate JWS; signature, aud and iss.
        # Token type, access token, ref-token and JWT
        if 0 == len(_config.get_issuer()):
            raise BadRequest('Could not validate token: no issuer configured')

        try:
            _jwt_validator.validate(token_data['id_token'], _config.get_issuer(), _config.get_client_id())
        except BadSignature as bs:
            raise BadRequest('Could not validate token: ' + str(bs))
        except Exception as ve:
            raise BadRequest('Unexpected exception: ' + str(ve))

        user.id_token = token_data['id_token']

    if 'refresh_token' in token_data:
        user.refresh_token = token_data['refresh_token']

    session['session_id'] = generate_random_string()
    _session_store[session['session_id']] = user

    return redirect('/')


if __name__ == '__main__':
    _config = Config()
    _client = Client(_config)
    _jwt_validator = JwtValidator(_config)
    # create a session store TODO: implement in some DB
    _session_store = {}

    # Flask session secret key
    app.secret_key = generate_random_string()

    # app.run(host='127.0.0.1', port=22222, threaded=True)
    app.run(debug=True)
