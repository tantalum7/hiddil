
import jsonschema

BLOCK_PUT = {'type': 'object',
             'required': ['data', 'pubkey_id', 'address', 'signature', 'expiration'],
             'properties': {'data': {'type': 'string', 'minLength': 1, 'maxLength': 1000},
                            'pubkey_id': {'type': 'string', 'maxLength': 32},
                            'address': {'type': 'string', 'minLength': 30, 'maxLength': 60},
                            'signature': {'type': 'string'},
                            'expiration': {'type': 'number', 'multipleOf': 1.0}}}

BLOCK_GET = {'type': 'object',
             'required': ['address', 'pubkey_id', 'signature'],
             'properties': {'address': {'type': 'string', 'minLength': 32, 'maxLength': 32},
                            'pubkey_id': {'type': 'string', 'minLength': 100, 'maxLength': 1000},
                            'signature': {'type': 'string'}}}

SALT_GET = {'type': 'object',
            'required': ['pubkey'],
            'properties': {'pubkey': {'type': 'string', 'minLength': 100, 'maxLength': 1000}}}

UPLOAD = {'type': 'object',
          'required': ['data_chunk_b64', 'rolling_hash', 'pubkey_id'],
          'properties': {'data_chunk_b64': {'type': 'string', 'maxLength': 1000},
                         'rolling_hash': {'type': 'string', 'maxLength': 32},
                         'pubkey_id': {'type': 'string', 'maxLength': 32}}}

DOWNLOAD = {'type': 'object',
            'required': ['last_chunk_good' 'pubkey_id'],
            'properties': {'last_chunk_good': {'type': 'boolean'},
                           'pubkey_id': {'type': 'string', 'maxLength': 32}}}

class JsonData(object):
    pass


def validateJSON(json_dict, schema):

    # Validate json against schema
    jsonschema.validate(json_dict, schema)

    # Create a JsonData object, stuff it with json dict
    json_data = JsonData()
    json_data.__dict__.update(json_dict)

    # Return the json data object
    return json_data

