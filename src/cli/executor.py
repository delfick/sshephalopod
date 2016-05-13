from lxml import etree as ET
from dancer import Okta
import argparse
import requests
import base64
import json
import os

def get_parser():
    parser = argparse.ArgumentParser("sshephelopod connector")
    parser.add_argument("--idp-type"
        , default = "okta"
        , choices = ["okta"]
        )

    parser.add_argument("--sp-url"
        , default = "https://sshephalopod.stg.company.com.au/signing"
        )

    parser.add_argument("--sp-api-key"
        , required = True
        )

    parser.add_argument("--public-key-location"
        , default = os.path.expanduser("~/.ssh/id_rsa.pub")
        , type = argparse.FileType('r')
        )

    kwargs = {}
    if "USER" in os.environ:
        kwargs["default"] = os.environ["USER"]
    else:
        kwargs['required'] = True
    parser.add_argument("--user-name"
        , **kwargs
        )

    parser.add_argument("--host"
        , required = True
        )

    return parser

def main(argv=None):
    args = get_parser().parse_args(argv)

    res = requests.get(args.sp_url, headers={"x-api-key": args.sp_api_key})
    if res.status_code != 200:
        raise Exception("Failed to get the authn_request\tstatus_code={0}\tcontent={1}".format(res.status_code, res.content.decode('utf-8')))

    authn_request = ET.fromstring(res.content.decode('utf-8'))
    if args.idp_type == "okta":
        dancer = Okta(authn_request)

    consumer_url = dict(authn_request.items())["AssertionConsumerServiceURL"]

    data = {
          "SAMLResponse": base64.b64encode(dancer.dance()).decode('utf-8')
        , "SSHPublicKey": args.public_key_location.readlines()[0].strip()
        , "UserName": args.user_name
        , "Host": args.host
        }

    res = requests.post(consumer_url, json=data, headers={"x-api-key": args.sp_api_key, "Content-Type": "application/json"})
    if res.status_code != 200:
        raise Exception("Failed to sign request\tstatus_code={0}\tcontent={1}".format(res.status_code, res.content.decode('utf-8')))

    try:
        content = json.loads(res.content.decode('utf-8'))
    except (TypeError, ValueError):
        raise Exception("Failed to sign request\tcontent={0}".format(res.content.decode('utf-8')))

    print("Sign in with {0}@{1}".format(args.user_name, args.host))
    print(base64.b64decode(content["SignedKey"]).decode('utf-8'))

if __name__ == "__main__":
    main()

