

class KeyImportException(Exception): pass
class BadBlockParametersException(Exception): pass
class KeyNotSaltedException(Exception): pass
class SignatureVerifyFailException(Exception): pass
class PutDataHashException(Exception): pass
class RollingHashException(Exception): pass
class UploadOverflowException(Exception): pass