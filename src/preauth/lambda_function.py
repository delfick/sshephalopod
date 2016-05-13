from common import install_deps

def preauth(event, context=None):
    install_deps()
    from preauth import handler
    return handler(event)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description = "Identity management!"
    )

    parser.add_argument("--callback_url"
        , default = "https://sshephalopod.stg.company.com.au/signing"
        )

    parser.add_argument("--idp-metadata-endpoint"
        , default = "https://company.okta.com/app/<id>/sso/saml/metadata"
        )

    args = parser.parse_args()

    event = {"callback_url": args.callback_url, "idp_metadata_endpoint": args.idp_metadata_endpoint}
    preauth(event, context)

