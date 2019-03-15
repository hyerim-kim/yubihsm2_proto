from asn1crypto import keys
from cryptography.hazmat.primitives import serialization
from secp256k1 import PublicKey
from yubihsm import YubiHsm
from yubihsm.objects import AsymmetricKey
from yubihsm.defs import OBJECT

hsm = YubiHsm.connect('http://localhost:12345')
session = hsm.create_session_derived(1, 'password')

key = session.get_object(0x260d, OBJECT.ASYMMETRIC_KEY)
pub_key = key.get_public_key()
der_pub = pub_key.public_bytes(
    encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
print(f"der11111 : {der_pub}")
key_info = keys.PublicKeyInfo.load(der_pub)
native_pub = key_info['public_key'].native
raw_pubkey_of_pair = PublicKey().deserialize(native_pub)
serialized_pubkey_of_pair = PublicKey(raw_pubkey_of_pair).serialize(compressed=False)
print(f"serialized_pubkey_of_pair : {serialized_pubkey_of_pair}")
