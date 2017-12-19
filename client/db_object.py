import json
from client.client import dict_key_to_camel_case


class BaseDbObject(object):
    def to_dict(self) -> dict:
        ret = {}
        for key, value in self.__dict__.items():
            pos = str(key).find("__")
            if 0 < pos:
                key = str(key)[pos:]
            if str(key).startswith("__") and not str(key).endswith("_") and value is not None:
                if isinstance(value, dict):
                    for par_key, par_value in value.items():
                        ret[dict_key_to_camel_case(par_key)] = par_value
                else:
                    ret[dict_key_to_camel_case(key)] = value
        return ret

    def __str__(self) -> str:
        return json.dumps(self.to_dict())
