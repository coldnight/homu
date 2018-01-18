import github3
import logging
import subprocess
import sys
import traceback
import requests
import time


def remove_url_keys_from_json(json):
    if isinstance(json, dict):
        return {key: remove_url_keys_from_json(value)
                for key, value in json.items()
                if not key.endswith('url')}
    elif isinstance(json, list):
        return [remove_url_keys_from_json(value) for value in json]
    else:
        return json


def lazy_debug(logger, f):
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f())


def logged_call(args):
    try:
        subprocess.check_call(args, stdout=subprocess.DEVNULL, stderr=None)
    except subprocess.CalledProcessError:
        print('* Failed to execute command: {}'.format(args))
        raise


def silent_call(args):
    return subprocess.call(
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def retry_until(inner, fail, state):
    err = None
    exc_info = None

    for i in range(3, 0, -1):
        try:
            inner()
        except (github3.models.GitHubError, requests.exceptions.RequestException) as e:  # noqa
            print('* Intermittent GitHub error: {}'.format(e), file=sys.stderr)

            err = e
            exc_info = sys.exc_info()

            if i != 1:
                time.sleep(1)
        else:
            err = None
            break

    if err:
        print('* GitHub failure in {}'.format(state), file=sys.stderr)
        traceback.print_exception(*exc_info)

        fail(err)
