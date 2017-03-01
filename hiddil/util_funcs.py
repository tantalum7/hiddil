
# Library imports
import collections
import random
import string
from flask import jsonify
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

def GenerateRandomCharString(num_chars):
    return ''.join(random.choice(string.ascii_uppercase + string.digits)for x in xrange(32))

def ConvertCompValueIntoShorthand(value_string):
    return re.sub(r'(\d+)(?:\.(\d+))(\w).*', r"\1\3\2", value_string).upper()