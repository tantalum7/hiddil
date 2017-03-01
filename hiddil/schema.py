
import jsonschema

BLOCK_PUT = { 'type'        : 'object',
              'required'    : ['data', 'pubkey_id', 'signature', 'expiration'],
              'properties'  : { 'data'                  : {'type' : 'string', 'minLength' : 8, 'maxLength' : 11000},
                                'pubkey_id'             : {'type' : 'string', 'maxLength' : 1000},
                                'signature'             : {'type' : 'string'},
                                'expiration'            : {'type' : 'number', 'multipleOf': 1.0},
                              }
            }

BLOCK_GET = { 'type'        : 'object',
              'required'    : ['address', 'pubkey_id', 'signature'],
              'properties'  : { 'address'               : {'type' : 'string', 'minLength' : 32, 'maxLength' : 32},
                                'pubkey'                : {'type' : 'string', 'minLength' : 100, 'maxLength' : 1000},
                                'signature'             : {'type' : 'string'},
                              }
            }

SALT_GET = { 'type'         : 'object',
             'required'     : ['pubkey'],
             'properties'   : { 'pubkey'                : {'type' : 'string', 'minLength' : 100, 'maxLength' : 1000},
                              }
            }

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

