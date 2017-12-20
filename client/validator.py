import json
import base64
from urllib.request import Request, urlopen
from jose import jws
from jose.constants import ALGORITHMS
from jose.exceptions import JWSError
from client.client import get_ssl_context
from client.config import Config


def base64_urldecode(s):
    ascii_string = str(s)
    ascii_string += '=' * (4 - (len(ascii_string) % 4))
    return base64.urlsafe_b64decode(ascii_string)


class JwtValidatorException(Exception):
    pass


class JwtValidator:
    def __init__(self, config: Config):
        print('Getting ssl context for jwks_uri')
        self.ctx = get_ssl_context(config)

        self.jwks_uri = config.get_jwks_uri()
        self.jwks = self.get_jwks_data()

    def validate(self, jwt, iss, aud):
        parts = jwt.split('.')
        if len(parts) != 3:
            raise JwtValidatorException('Invalid JWT. Only JWS supported.')
        payload = json.loads(base64_urldecode(parts[1]))

        if iss != payload['iss']:
            raise JwtValidatorException("Invalid issuer %s, expected %s" % (payload['iss'], iss))

        if payload["aud"]:
            if (isinstance(payload["aud"], str) and payload["aud"] != aud) or aud not in payload['aud']:
                raise JwtValidatorException("Invalid audience %s, expected %s" % (payload['aud'], aud))

        try:
            jws.verify(jwt, self.jwks, ALGORITHMS.ALL)
        except JWSError as e:
            print("Exception validating signature")
            raise JwtValidatorException(e)

        print("Successfully validated signature.")

    def get_jwks_data(self):
        request = Request(self.jwks_uri)
        request.add_header('Accept', 'application/json')
        request.add_header('User-Agent', 'CurityExample/1.0')

        try:
            jwks_response = urlopen(request, context=self.ctx)
        except Exception as e:
            print("Error fetching JWKS", e)
            raise e
        return jwks_response.read()
