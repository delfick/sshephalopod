from common import install_deps
from tempfile import mkdtemp
import subprocess
import base64
import pickle
import shutil
import sys
import os

def postauth_lambda(event, context, tmpdir=None):
    current_ld_path = ""
    if "LD_LIBRARY_PATH" in os.environ:
        current_ld_path = ":{0}".format(os.environ["LD_LIBRARY_PATH"])
    deps_path = os.path.join(os.path.dirname(__file__), "deps/libxmlsec")

    # I need LD_LIBRARY_PATH for xmlsec because of pysaml
    # This means I need to restart python with the new LD_LIBRARY_PATH :(
    environ = dict(os.environ)
    environ["LD_LIBRARY_PATH"] = "{0}-linux{1}".format(deps_path, current_ld_path)

    if tmpdir is None:
        tmpdir = mkdtemp()
    filename = os.path.join(tmpdir, "result")

    # This makes me laugh
    process = subprocess.Popen([sys.executable, "-c",  "from lambda_function import postauth; import pickle; pickle.dump(postauth({0}, None), open('{1}', 'w'))".format(event, filename)], env=environ, stderr=subprocess.PIPE)
    process.wait()

    if process.poll() != 0:
        print(process.stderr.read())
        raise Exception("Failed!, please see logs for the lambda function ({0} - {1})".format(context.invoked_function_arn, context.aws_request_id))

    # And finally, we return the result so apigateway can get to it
    return pickle.load(open(filename))

def postauth(event, context):
    install_deps()
    from postauth import handler
    return handler(event)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description = "Identity management!"
    )

    parser.add_argument("--saml-response"
        , required = True
        )

    parser.add_argument("--ca-key"
        , required = True
        , type = argparse.FileType('r')
        )

    parser.add_argument("--public-key-location"
        , default = os.path.expanduser("~/.ssh/id_rsa.pub")
        , type = argparse.FileType("r")
        )

    parser.add_argument("--user-name"
        , default = os.environ['USER']
        )

    parser.add_argument("--host"
        , required = True
        )

    parser.add_argument("--idp-metadata-endpoint"
        , default = "https://company.okta.com/app/<id>/sso/saml/metadata"
        )

    args = parser.parse_args()

    event = {
          "Body":
          { "SSHPublicKey": args.public_key_location.readlines()[0].strip()
          , "SAMLResponse": base64.b64encode(args.saml_response)
          , "UserName": args.user_name
          , "Host": args.host
          }
        , "ca_key": {"plain": args.ca_key.read()}
        , "idp_metadata_endpoint": args.idp_metadata_endpoint
        }

    tmpdir = None
    try:
        tmpdir = mkdtemp()
        print(base64.b64decode(postauth_lambda(event, None)["SignedKey"]))
    finally:
        if tmpdir and os.path.exists(tmpdir):
            shutil.rmtree(tmpdir)

