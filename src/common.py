from contextlib import contextmanager
import platform
import site
import sys
import os

def ensure_is_integer(value, name):
    """Raise an exception if the value is not an integer"""
    is_int_or_float = type(value) in (int, float)
    is_string_digit = isinstance(value, basestring) and value.isdigit()

    if not (is_int_or_float or is_string_digit):
        raise Failure("Provided {0} was not an integer".format(name), {})

class Failure(Exception):
    def __init__(self, message, output):
        self.message = message
        self.output = output

class Success(Exception):
    def __init__(self, output):
        self.output = output

@contextmanager
def success_or_failure(event, reference):
    result = {}
    notes = event.get("notes", "")

    try:
        yield result

        # We expect a Failure or Success to have been risen
        raise Exception("This should never happen")

    except Failure as error:
        result.update({
              "status": "CRITICAL", "error": error.message
            , "input": event, "outputs": error.output
            , "reference": reference, "notes": notes
            })

    except Success as success:
        result.update({
              "status": "OK"
            , "input": event, "outputs": success.output
            , "reference": reference, "notes": notes
            })

def install_deps():
    deps_folder = os.path.join(os.path.dirname(__file__), "deps")

    # Add any normal dependencies
    sys.path.extend([deps_folder])

    # Add in our site-packages dirs
    is_macosx = platform.platform().startswith("Darwin")
    site_packages_folders = os.path.join(deps_folder, "site-packages-folders")

    if os.path.exists(site_packages_folders):
        for name in os.listdir(site_packages_folders):
            if name.endswith("-macosx") or name.endswith("-linux"):
                if is_macosx and name.endswith("-linux"):
                    continue
                elif not is_macosx and name.endswith("-macosx"):
                    continue

            site.addsitedir(os.path.join(deps_folder, "site-packages-folders", name))
