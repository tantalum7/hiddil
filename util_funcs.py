
# Library imports
import collections
import random
import string
from flask import make_response
import json
import re

def recursive_dict_update(d, u):
    for k, v in u.iteritems():
        if isinstance(v, collections.Mapping):
            r = recursive_dict_update(d.get(k, {}), v)
            d[k] = r
        else:
            d[k] = u[k]
    return d

def BadJsonResponse(data, status_code=401):
    response = make_response(json.dumps(data), status_code)
    response.headers['Content-Type'] = 'application/json'
    return response

def GoodJsonResponse(data, status_code=200):
    response = make_response(json.dumps(data), status_code)
    response.headers['Content-Type'] = 'application/json'
    return response

def GenerateRandomCharString(num_chars):
    return ''.join(random.choice(string.ascii_uppercase + string.digits)for x in range(32))

def ConvertCompValueIntoShorthand(value_string):
    return re.sub(r'(\d+)(?:\.(\d+))(\w).*', r"\1\3\2", value_string).upper()