import json
import random
import string
from ssl import create_default_context
from _ssl import CERT_NONE
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import URLError
from client.config import Config


def generate_random_string():
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))


def get_ssl_context(config: Config):
    ctx = create_default_context()

    if not config.verify_ssl_server():
        print('Not verifying ssl certificates')
        ctx.check_hostname = False
        ctx.verify_mode = CERT_NONE
    return ctx


class Client:
    def __init__(self, config: Config):
        self.config: Config = config

        print('Getting ssl context for oauth server')
        self.ctx = get_ssl_context(self.config)
        self.__init_config()

    def __init_config(self):
        if self.config.get_discovery_url() is not None and len(self.config.get_discovery_url()) > 0:
            discovery = self.urlopen(self.config.get_discovery_url(), context=self.ctx)
            self.config.set_discovery_content(json.loads(discovery.read()))
        else:
            print("No discovery url configured, all endpoints needs to be configured manually")

        # Mandatory settings
        if 0 == len(self.config.get_authorization_endpoint()):
            raise Exception('authorization_endpoint not set.')
        if 0 == len(self.config.get_token_endpoint()):
            raise Exception('token_endpoint not set.')
        if 0 == len(self.config.get_client_id()):
            raise Exception('client_id not set.')
        if 0 == len(self.config.get_client_secret()):
            raise Exception('client_secret not set.')
        if 0 == len(self.config.get_redirect_uri()):
            raise Exception('redirect_uri not set.')

    def revoke(self, token):
        """
        Revoke the token
        :param token: the token to revoke
        :raises: raises error when http call fails
        """
        if 0 == len(self.config.get_revocation_endpoint()):
            print('No revocation endpoint set')
            return

        data = {
            'token': token,
            'client_id': self.config.get_client_id(),
            'client_secret': self.config.get_client_secret()
        }
        self.urlopen(self.config.get_revocation_endpoint(), urlencode(data), context=self.ctx)

    def refresh(self, refresh_token):
        """
        Refresh the access token with the refresh_token
        :param refresh_token:
        :return: the new access token
        """
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.config.get_client_id(),
            'client_secret': self.config.get_client_secret()
        }
        token_response = self.urlopen(self.config.get_token_endpoint(), urlencode(data), context=self.ctx)
        return json.loads(token_response.read())

    def get_authn_req_url(self, session, acr, force_auth_n):
        state = generate_random_string()
        session['state'] = state
        request_args = self.__authn_req_args(state)
        if acr:
            request_args["acr_values"] = acr
        if force_auth_n:
            request_args["prompt"] = "login"
        login_url = "%s?%s" % (self.config.get_authorization_endpoint(), urlencode(request_args))
        print("Redirect to federation service %s" % login_url)
        return login_url

    def get_token(self, code):
        """
        :param code: The authorization code to use when getting tokens
        :return the json response containing the tokens
        """
        data = {'client_id': self.config.get_client_id(), "client_secret": self.config.get_client_secret(),
                'code': code,
                'redirect_uri': self.config.get_redirect_uri(),
                'grant_type': 'authorization_code'}

        # Exchange code for tokens
        try:
            token_response = self.urlopen(self.config.get_token_endpoint(), urlencode(data), context=self.ctx)
        except URLError as te:
            print("Could not exchange code for tokens")
            raise te
        return json.loads(token_response.read())

    @staticmethod
    def urlopen(url, data=None, context=None):
        headers = {
            'User-Agent':
                'CurityExample/1.0',
            'Accept':
                'application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
        }
        
        request = Request(url, data, headers)
        return urlopen(request, context=context)

    def __authn_req_args(self, state):
        """
        :param state: state to send to authorization server
        :return a map of arguments to be sent to the authz endpoint
        """
        args = {'scope': self.config.get_scope(),
                'response_type': 'code',
                'client_id': self.config.get_client_id(),
                'state': state,
                'redirect_uri': self.config.get_redirect_uri()}

        if 0 == len(self.config.get_authn_parameters()):
            args.update(self.config.get_authn_parameters())
        return args
