
# Library imports
import jsonschema
from jsonschema import ValidationError


BLOCK_PUT = {'type': 'object',
             'required': ['pubkey_id', 'block_num', 'signature', 'expiration', 'chunked', 'size'],
             'properties': {'data': {'type': 'string', 'minLength': 1, 'maxLength': 1000},
                            'pubkey_id': {'type': 'string', 'maxLength': 32},
                            'block_num': {'type': 'number', 'multipleOf': 1.0},
                            'signature': {'type': 'string'},
                            'expiration': {'type': 'number', 'multipleOf': 1.0},
                            'chunked': {'enum': [True, False]},
                            'size': {'type': 'number', 'multipleOf': 1.0}}}

BLOCK_GET = {'type': 'object',
             'required': ['block_num', 'pubkey_id', 'signature'],
             'properties': {'block_num': {'type': 'number', 'multipleOf': 1.0},
                            'pubkey_id': {'type': 'string', 'maxLength': 1000},
                            'signature': {'type': 'string'}}}

SALT_GET = {'type': 'object',
            'required': ['pubkey'],
            'properties': {'pubkey': {'type': 'string', 'maxLength': 1000}}}

UPLOAD = {'type': 'object',
          'required': ['data_chunk_b64', 'rolling_hash', 'pubkey_id'],
          'properties': {'data_chunk_b64': {'type': 'string', 'maxLength': 1000},
                         'rolling_hash': {'type': 'string', 'maxLength': 100},
                         'pubkey_id': {'type': 'string', 'maxLength': 32}}}

DOWNLOAD = {'type': 'object',
            'required': ['last_chunk_good' 'pubkey_id'],
            'properties': {'last_chunk_good': {'type': 'boolean'},
                           'pubkey_id': {'type': 'string', 'maxLength': 32}}}


def validate_json(json_dict: dict, json_schema: dict):
    jsonschema.validate(json_dict, json_schema)
    return json_dict