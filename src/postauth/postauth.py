from onelogin.saml2.utils import OneLogin_Saml2_Utils
from Crypto.Signature import PKCS1_v1_5
from paramiko.message import Message
from Crypto.PublicKey import RSA
from six.moves import StringIO
from lxml import etree as ET
from Crypto.Hash import SHA
from textwrap import dedent
from hashlib import sha1
import paramiko
import datetime
import requests
import random
import base64

DURATION_HOURS = "12"

SSH_CERT_TYPE_USER = 1
SSH_CERT_TYPE_HOST = 2

def handler(event):
    host = event['Body']['Host']
    saml_response = event['Body']["SAMLResponse"]
    body_username = event['Body']["UserName"]
    ssh_public_key = event["Body"]['SSHPublicKey']

    ca_key = event["ca_key"]
    idp_metadata_endpoint = event['idp_metadata_endpoint']

    # Need to work out which IDP to pull the metadata for
    response = base64.b64decode(saml_response)
    idp_path = ".//*[local-name()='Issuer']/text()"
    responsedoc = ET.fromstring(response)
    idp = str(responsedoc.xpath(idp_path)[0])

    print("Getting metadata from {0}".format(idp_metadata_endpoint))
    data = retrieve_metadata(idp_metadata_endpoint)
    doc = ET.fromstring(data)

    path = "/*[local-name()='Response' and namespace-uri() = 'urn:oasis:names:tc:SAML:2.0:protocol']"
    saml2_response = ET.tostring(responsedoc.xpath(path)[0])

    profile, logged_out = saml_validate_post_response(saml2_response)
    if logged_out:
        raise Exception("User has been logged out")

    print("Retrieving real name from XML");
    path = ".//*[local-name()='Attribute' and @Name='email']/*[local-name()='AttributeValue']/text()";
    real_name = responsedoc.xpath(path)[0]
    print("Got realName of {0}".format(real_name))

    now = datetime.datetime.now()
    expiry = now + datetime.timedelta(hours=int(DURATION_HOURS))
    priv_key = decrypt_key(ca_key)

    certificate = make_certificate(priv_key, DURATION_HOURS, real_name, body_username, host, now, expiry)

    return_data = {
          "Result": True
        , "Message": "Authentication succeeded"
        , "Expiry": expiry.isoformat()
        , "SignedKey": base64.b64encode(certificate)
        }

    return return_data

def saml_validate_post_response(response):
    issuer = 'urn:rea:sshephalopod'
    request_id_expiration_period_ms = 3600000

    xml = ET.fromstring(response)
    path = "/*[local-name()='Response']/@InResponseTo"
    in_response_to = xml.xpath(path)
    in_response_to = in_response_to[0] if in_response_to else ""

    path = ".//*[local-name()='X509Certificate']/text()"
    cert = xml.xpath(path)[0]
    cert = "-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----".format(cert)

    if not OneLogin_Saml2_Utils.validate_sign(xml, cert, validatecert=True):
        raise Exception("Top level signature is not valid!")

    assertions = xml.xpath("/*[local-name()='Response']/*[local-name()='Assertion']")
    encrypted_assertions = xml.xpath("/*[local-name()='Response']/*[local-name()='EncryptedAssertion']")
    if len(assertions) + len(encrypted_assertions) > 1:
        # There's apparently no reason we want to handle multiple assertions
        raise Exception("Too many assertions!")

    if len(assertions) == 1:
        if not OneLogin_Saml2_Utils.validate_sign(assertions[0], cert, validatecert=True):
            raise Exception("Invalid signature in assertion")
        return process_validly_signed_assertion(ET.tostring(assertions[0]))

    raise NotImplementedError("Sorry, only know about if there is an assertion in the response")

def check_timestamps_validity(nowms, not_before, not_on_or_after):
    if not_before:
        not_before_ms = int(datetime.datetime.strptime(not_before, '%Y-%m-%dT%H:%M:%S.%fZ').strftime("%s"))
        if nowms < not_before_ms:
            raise Exception("SAML Assertion not yet valid")

    if not_on_or_after:
        not_on_or_after_ms = int(datetime.datetime.strptime(not_on_or_after, '%Y-%m-%dT%H:%M:%S.%fZ').strftime("%s"))
        if nowms >= not_on_or_after_ms:
            raise Exception("SAML Assertion expired\tseconds_ago={0}".format(nowms-not_on_or_after_ms))

def process_validly_signed_assertion(assertion):
    profile = {}

    nowms = int(datetime.datetime.utcnow().strftime("%s"))
    xml = ET.fromstring(assertion)

    profile['issuer'] = xml.xpath(".//*[local-name()='Issuer']")[0].text
    profile['sessionIndex'] = dict(xml.xpath(".//*[local-name()='AuthnStatement']")[0].items())['SessionIndex']

    name_id = xml.xpath(".//*[local-name()='Subject']/*[local-name()='NameID']")
    if name_id:
        profile["nameID"] = name_id[0].text

        frmt = dict(name_id[0].items()).get("Format")
        if frmt:
            profile["nameIDFormat"] = frmt

    subject_confirmation_data = xml.xpath(".//*[local-name()='Subject']/*[local-name()='SubjectConfirmation']/*[local-name()='SubjectConfirmationData']")
    if len(subject_confirmation_data) > 1:
        raise Exception("Unable to process multiple SubjectConfirmations in SAML assertion")

    if subject_confirmation_data:
        items = dict(subject_confirmation_data[0].items())
        subject_not_before = items.get("NotBefore")
        subject_not_on_or_after = items.get("NotOnOrAfter")
        check_timestamps_validity(nowms, subject_not_before, subject_not_on_or_after)

    conditions = xml.xpath(".//*[local-name()='Conditions']")
    if len(conditions) > 1:
        raise Exception("Unable to process multiple conditions in SAML assertion")

    if conditions:
        items = dict(conditions[0].items())
        condition_not_before = items.get("NotBefore")
        condition_not_on_or_after = items.get("NotOnOrAfter")
        check_timestamps_validity(nowms, condition_not_before, condition_not_on_or_after)

    attributes = xml.xpath(".//*[local-name()='AttributeStatement']/*[local-name()='Attribute']")
    if attributes:
        for attribute in attributes:
            value = attribute.xpath("./*[local-name()='AttributeValue']")
            if len(value) is 1:
                profile[dict(attribute.items())["Name"]] = value[0].text
            else:
                raise NotImplementedError("Sorry, can't handle attributes with multiple AttributeValues")

    if 'mail' not in profile and 'urn:oid:0.9.2342.19200300.100.1.3' in profile:
        profile['mail'] = profile['urn:oid:0.9.2342.19200300.100.1.3']

    if 'email' not in profile:
        profile['email'] = profile['mail']

    return profile, False

def make_certificate(ca_key, duration_hours, real_name, username, host, now, expiry):
    """http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?rev=1.9"""
    pkey = paramiko.RSAKey.from_private_key(StringIO(ca_key))

    principals = Message()
    principals.add_string(username)
    principals = principals.asbytes()

    m = Message()
    m.add_string('ssh-rsa-cert-v01@openssh.com')
    m.add_string(sha1(str(random.random())).hexdigest())
    m.add_mpint(pkey.e)
    m.add_mpint(pkey.n)
    m.add_int64(0) # serial
    m.add_int(SSH_CERT_TYPE_USER)
    m.add_string(real_name)
    m.add_string(principals)
    m.add_int64(int(now.strftime("%s")))
    m.add_int64(int(expiry.strftime("%s")))
    m.add_string("") # critical_options
    m.add_string("") # extensions
    m.add_string("") # reserved
    m.add_string(pkey.asbytes())

    key = RSA.construct((long(pkey.n), long(pkey.e), long(pkey.d)))
    h = SHA.new(m.asbytes())
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(h)

    sig_message = Message()
    sig_message.add_string("ssh-rsa")
    sig_message.add_string(signature)
    m.add_string(sig_message.asbytes())

    return "ssh-rsa-cert-v01@openssh.com {0} {1}@{2}".format(base64.b64encode(m.asbytes()), username, host)

def decrypt_key(key):
    if "plain" in key:
        return key["plain"]
    import boto3
    return boto3.client("kms", "ap-southeast-2").decrypt(CiphertextBlob=base64.b64decode(key["kms"]))["Plaintext"]

def retrieve_metadata(idp_url):
    print('Retrieving metadata from {0}'.format(idp_url))
    if not idp_url:
        raise Exception("No idp url was specified (IdpMetadataEndpoint in the event)")

    if not idp_url.startswith("https"):
        raise Exception("Idp url wasn't https\tidp_url={0}".format(idp_url))

    res = requests.get(idp_url)
    print("Status code: {0}".format(res.status_code))
    print('Status message: {0}'.format(res.reason))

    return res.content

