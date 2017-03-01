
# Library imports
from pymongo    import MongoClient, ASCENDING, DESCENDING
from bson       import objectid
from time       import time

class OperationResult(object):

    def __init__(self, success=False, op_count=None, message=None, inserted_ids=None, modified_ids=None):

        # Init class vars
        self.success        = success
        self.op_count       = op_count
        self.message        = message
        self.inserted_ids   = inserted_ids
        self.modified_ids   = modified_ids

    @property
    def success(self):
        return self._success

    @success.setter
    def success(self, value):
        self._success = bool(value)

    @property
    def op_count(self):
        return self._op_count

    @op_count.setter
    def op_count(self, value):
        self._op_count = None if value is None else int(value)

    @property
    def inserted_ids(self):
        return self._inserted_ids

    @inserted_ids.setter
    def inserted_ids(self, value):
        self._inserted_ids = [] if value is None else list(value)

    @property
    def modified_ids(self):
        return self._modified_ids

    @modified_ids.setter
    def modified_ids(self, value):
        self._modified_ids = [] if value is None else [value]

    @property
    def message(self):
        return self._message

    @message.setter
    def message(self, value):
        self._message = None if value is None else str(value)

    def __nonzero__(self):
        return bool(self.success)


class SearchResult(object):

    def __init__(self, pymongo_cursor):
        self._pymongo_cursor = pymongo_cursor

    def __getitem__(self, *args):
        return self._pymongo_cursor.__getitem__(*args)

    def __len__(self):
        return self._pymongo_cursor.count()
    #
    # def __iter__(self):
    #     return self._pymongo_cursor.next()

    def __nonzero__(self):
        return bool( self.__len__() )

    def sort(self, field, ascending=True):
        self._pymongo_cursor.sort(field, ASCENDING if ascending else DESCENDING)

    def as_list(self):
        return [data for data in self]


def _cached(f):

    def _create_cache_key(f, arg_list, kwarg_dict):
        key_dict = { "NAME" : str(f.__name__) }
        key_dict.update( {i : str(v) for i, v in enumerate(arg_list)} )
        key_dict.update( kwarg_dict )
        key_list = [ ":".join([str(k), str(key_dict[k])]) for k in sorted(key_dict.keys()) ]
        key_str = "#".join(key_list)
        return xxh.hash32(key_str)

    def wrapper(*args, **kwargs):

        t = time()

        cache = args[0].cache

        # Prepare key
        key = _create_cache_key(f, args, kwargs)

        # Check if there is a valid result in the cache
        try:
            cached_result = cache.get(key)

        except KeyError:
            print "No cached result found for"+str(key)
            result = f(*args, **kwargs)
            cache.add(key, result)
            print "Wrapper took {}s".format(time() - t)
            return result

        except:
            raise

        else:
            print "Returning cached result"
            print "Wrapper took {}s".format(time() - t)
            return cached_result

    return wrapper


class _SimpleCache(object):

    class _SimpleCacheObject(object):
        def __init__(self, key, value, lifespan):
            self.key            = key
            self.value          = value
            self.lifespan       = lifespan
            self.creation_time  = time()
            self.access_count   = 0

        def is_alive(self):
            return time() - self.creation_time < self.lifespan

    def __init__(self, default_lifespan=60):
        self.default_lifespan   = default_lifespan
        self._cache_objects     = {}

    def add(self, key, value, lifespan=None):
        self._cache_objects[key] = self._SimpleCacheObject(key=key, value=value,
                                                           lifespan=self.default_lifespan if lifespan is None else lifespan)

    def get(self, key):

        if not self._cache_objects[key].is_alive():
            del self._cache_objects[key]
            raise KeyError()

        self._cache_objects[key].access_count += 1
        return self._cache_objects[key].value

    def clear_item(self, key):
        self._cache_objects.pop(key, None)

    def clear_all(self):
        self._cache_objects = {}


class Database(object):

    def __init__(self, ip_port_tuple):

        # Create db client object
        self.client = MongoClient(*ip_port_tuple)

        # Create ref to manf database assets collection
        self.db = self.client.blockstore.blocks

        # Create local memory cache
        self.cache = _SimpleCache()

    # CRUD

    def update_one(self, filter, data):
        mongo_result = self.db.update_one(filter=filter, update=data, upsert=False)
        return OperationResult(success  = mongo_result.acknowledged,
                               op_count = mongo_result.modified_count)

    def update_many(self, filter, data):
        mongo_result = self.db.update_many(filter=filter, update=data, upsert=False)
        return OperationResult(success  = mongo_result.acknowledged,
                               op_count = mongo_result.modified_count)

    #@_cached
    def find_one(self, filter=None, projection=None, sort=None, ignore_cache=False):
        return self.db.find_one(filter=filter, projection=projection, sort=sort)

    #@_cached
    def find_many(self, filter=None, projection=None, limit=0, sort=None, ignore_cache=False):
        return SearchResult( self.db.find(filter=filter, projection=projection, limit=limit, sort=sort) )

    def insert_one(self, data):
        mongo_result = self.db.insert_one(document=data)
        return OperationResult(success      = mongo_result.acknowledged,
                               op_count     = 1 if mongo_result.acknowledged else 0,
                               inserted_ids = [mongo_result.inserted_id])

    def insert_many(self, data_set):
        mongo_result = self.db.insert_many(documents=data_set)
        return OperationResult(success      = mongo_result.acknowledged,
                               op_count     = len(mongo_result.inserted_ids),
                               inserted_ids = mongo_result.inserted_ids)

    def delete_one(self, filter):
        mongo_result = self.db.delete_one(filter=filter)
        return OperationResult(success  = mongo_result.acknowledged,
                               op_count = mongo_result.deleted_count)

    def delete_many(self, filter):
        mongo_result = self.db.delete_many(filter=filter)
        return OperationResult(success  = mongo_result.acknowledged,
                               op_count = mongo_result.deleted_count)

    def id(self, id_string):
        return id_string if isinstance(id_string, objectid.ObjectId) else objectid.ObjectId(id_string)

    def _cache_key(self, arg_dict):
        return ",".join([":".join([str(k), str(v)]) for k, v in arg_dict.items()])




def my_deco(f):
    print "my_deco({})".format(f)
    return f

@_cached
def my_func(*args):
    return

if __name__ == "__main__":

    my_func({'1key' : '1value'}, "str_val", [1, 2, 3])
    my_func({'1key' : '1value'}, "str_val", [1, 2, 1])
    my_func({'1key' : '1value'}, "str_val", [1, 2, 3])
    my_func("str_val", {'1key' : '1value'}, [1, 2, 3])



    print "Done"