
# Library imports
import configparser


class SettingsObject:
    """
    Simple settings module parses from an ini file, and updates the Settings global dict members with it.
    Values defined in the class can be considered default values, which are replaced by ini settings
    if a one is provided.

    All relevant settings should be in a single 'server_settings' section
    The ini file parses tries to parse entries with '_INT' as a suffix as an int. Everything else is a string.
    The suffix is removed when used.
    """
    CHALLENGE_EXPIRE_TIME = 120
    TRUST_EXPIRE_TIME = 3600
    TRANSFER_EXPIRE_TIME = 120
    STORAGE_BACKEND = "sqlite3"
    STORAGE_PATH = "hiddil_sqlite3.db"


Settings = SettingsObject()


def _init():

    # Create a configparser instance, and read the ini file
    config = configparser.ConfigParser()
    config.read("server_settings.ini")

    # Iterate through key: value pairs in "server_settings section
    for key, value in config._sections.get("server_settings", {}).items():

        # Make sure key is uppercase
        key = key.upper()

        # Check if the key has an INT suffix
        if key.endswith("_INT"):

            # Try and parse the value string as an int
            try:
                value = int(value)

            # Parse failed, skip this key
            except ValueError:
                continue

            # Parse successful, remove the suffix and store the key: value pair in the class
            else:
                Settings.__dict__[key[:-4]] = value


_init()