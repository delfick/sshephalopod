from datetime import datetime
from lxml import etree as ET
from textwrap import dedent
from hashlib import sha1
from uuid import uuid4
import calendar
import requests
import base64
import json

def handler(event):
    print("Received event:", json.dumps(event))

    callback_url = event['callback_url']
    idp_metadata_endpoint = event["idp_metadata_endpoint"]

    print('Getting IDP metadata')
    data = retrieve_metadata(idp_metadata_endpoint)

    print('Got metadata: {0}', data)
    doc = ET.fromstring(data)
    path = ".//*[local-name()='SingleSignOnService']/@Location"
    sp_entity_id = doc.xpath(path)[0]
    print("SAML entrypoint: {0}".format(sp_entity_id))

    print("Making a saml request!")
    saml_options = get_saml_options(callback_url, idp_metadata_endpoint, sp_entity_id)
    login_request = construct_login_request(saml_options)

    print('Got login request: {0}'.format(login_request))
    return login_request

def construct_login_request(settings):
    """Borrowed from pysaml2.authn_request"""

    sp_data = settings["sp"]
    idp_data = settings["idp"]
    security = settings["security"]

    uid = 'SSHEPHALOPOD_{0}'.format(sha1(uuid4().hex).hexdigest())
    now = calendar.timegm(datetime.utcnow().utctimetuple())
    issue_instant = parse_time_to_SAML(now)

    destination = idp_data['singleSignOnService']['url']

    name_id_policy_format = sp_data['NameIDFormat']

    provider_name_str = ''
    is_passive_str = 'IsPassive="true"'
    force_authn_str = 'ForceAuthn="true"'

    requested_authn_context_str = dedent("""
        <samlp:RequestedAuthnContext Comparison="exact">
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
        </samlp:RequestedAuthnContext>
    """)

    # Indent requested_authn_context_str
    indent = " " * 12
    requested_authn_context_str = "\n".join("{0}{1}".format(indent, line) for line in requested_authn_context_str.split("\n"))

    # Options for our request string
    options = {
          'id': uid
        , 'entity_id': sp_data['entityId']
        , 'destination': destination
        , 'provider_name': provider_name_str
        , 'issue_instant': issue_instant
        , 'assertion_url': sp_data['assertionConsumerService']['url']
        , 'is_passive_str': is_passive_str
        , 'force_authn_str': force_authn_str
        , 'name_id_policy': name_id_policy_format
        , 'requested_authn_context_str': requested_authn_context_str
        }

    request = dedent("""
        <samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="{id}"
            Version="2.0"
            {provider_name}
            {force_authn_str}
            {is_passive_str}
            IssueInstant="{issue_instant}"
            Destination="{destination}"
            ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            AssertionConsumerServiceURL="{assertion_url}">
            <saml:Issuer>{entity_id}</saml:Issuer>
            <samlp:NameIDPolicy
                Format="{name_id_policy}"
                AllowCreate="true" />
            {requested_authn_context_str}
        </samlp:AuthnRequest>
    """.format(**options)).strip()

    return request

def get_saml_options(callback_url, idp_metadata_endpoint, sp_entity_id):
    return {
          # Security settings
          "security":
          { "requesetAuthnContext": True
          }

          # Service Provider Data that we are deploying.
        , "sp":
          { # Identifier of the SP entity  (must be a URI)
            "entityId": 'urn:company:sshephalopod'

            # Specifies info about where and how the <AuthnResponse> message MUST be
            # returned to the requester, in this case our SP.
          , "assertionConsumerService":
            { # URL Location where the <Response> from the IdP will be returned
              "url": callback_url
            }

            # Specifies the constraints on the name identifier to be used to
            # represent the requested subject.
            # Take a look on src/onelogin/saml2/constants.py to see the NameIdFormat that are supported.
          , "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"
          }

          # Identity Provider Data that we want connected with our SP.
        , "idp":
          { "singleSignOnService":
            { # URL Target of the IdP where the Authentication Request Message
              # will be sent.
              "url": sp_entity_id
            }
          }
        }

def retrieve_metadata(idp_url):
    print('Retrieving metadata from {0}'.format(idp_url))
    if not idp_url:
        raise Exception("No idp url was specified (IdpMetadataEndpoint in the event)")

    if not idp_url.startswith("https"):
        raise Exception("Idp url wasn't https\tidp_url={0}".format(idp_url))

    res = requests.get(idp_url)
    print("Status code: {0}".format(res.status_code))
    print('Status message: {0}'.format(res.reason))

    metadata = res.content
    print("Got metadata: {0}".format(metadata))

    return metadata

def parse_time_to_SAML(time):
    """
    Converts a UNIX timestamp to SAML2 timestamp on the form
    yyyy-mm-ddThh:mm:ss(\.s+)?Z.
    """
    data = datetime.utcfromtimestamp(float(time))
    return data.strftime('%Y-%m-%dT%H:%M:%SZ')

