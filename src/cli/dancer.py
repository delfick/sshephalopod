from six.moves.urllib.parse import urlparse
from lxml import html as ET
from getpass import getpass
from six.moves import input
import requests
import logging
import base64

class Okta(object):
    def __init__(self, authn_request):
        self.authn_request = authn_request

    @property
    def idp_destination(self):
        return dict(self.authn_request.items())['Destination']

    @property
    def idp_endpoint(self):
        options = urlparse(self.idp_destination)
        return "https://{0}/login/do-login".format(options.netloc)

    def dance(self):
        username = input("Okta username: ")
        password = getpass("Okta password: ")

        headers = {
              "User-Agent": "Mozilla/5.0 (compatible;  MSIE 7.01; Windows NT 5.0)"
            , "Cache-Control": "no-cache"
            , "Content-Type": "application/x-www-form-urlencoded"
            }

        data = {
              "hidden-password-1": ""
            , "hidden-password-2": "test"
            , "username": username
            , "password": password
            , "isChromeOs": ""
            , "login": "Sign+In"
            }

        session = requests.Session()
        res = session.post(self.idp_endpoint, headers=headers, data=data, allow_redirects=False)
        if res.status_code != 302:
            raise Exception("Failed to login\tstatus_code={0}\tcontent={1}".format(res.status_code, res.content.decode('utf-8')))

        res2 = session.post(self.idp_destination, headers=headers)
        if res2.status_code != 200:
            raise Exception("Failed to get response from the idp endpoint\tstatus_code={0}\tcontent={1}".format(res.status_code, res.content.decode('utf-8')))

        content = ET.fromstring(res2.content.decode('utf-8'))
        return base64.b64decode(content.cssselect('input[name="SAMLResponse"]')[0].value)

