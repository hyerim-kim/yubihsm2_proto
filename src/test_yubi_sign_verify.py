import hashlib
import struct

from asn1crypto import keys
from cryptography import utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes, asymmetric
from cryptography.hazmat.primitives.asymmetric import ec
from secp256k1 import PrivateKey, PublicKey, ffi
from yubihsm import YubiHsm
from yubihsm.defs import CAPABILITY, ALGORITHM, COMMAND
from yubihsm.objects import AsymmetricKey


def remove_unnecessary_keys(hsm_session):
    obj_list = hsm_session.list_objects()
    for obj in obj_list:
        if obj.get_info().id not in [int(0x3125), int(0x0064), int(0xbc60), int(0xc529)]:
            print(f"Deleted obj: {obj.get_info()}")
            obj.delete()
        else:
            print(f"Remained obj: {obj.get_info()}")


def convert_to_elliptic_curve_publickey(native: bytes):
    algorithm = ALGORITHM.EC_K256
    raw_key = native[1:]
    c_len = len(raw_key) // 2
    x = utils.int_from_bytes(raw_key[:c_len], 'big')
    y = utils.int_from_bytes(raw_key[c_len:], 'big')

    return ec.EllipticCurvePublicNumbers(curve=algorithm.to_curve(), x=x, y=y)


# Connect to the YubiHSM via the connector using the default password:
hsm = YubiHsm.connect('http://localhost:12345')
session = hsm.create_session_derived(1, 'password')

origin_data = b'Hello world!'
hash_algorithm = hashlib.sha3_256()
hash_algorithm.update(origin_data)
hashed_origin_data = hash_algorithm.digest()
# Generate a private key on the YubiHSM for creating signatures:
key = AsymmetricKey.generate(  # Generate a new key object in the YubiHSM.
    session,                   # Secure YubiHsm session to use.
    0,                         # Object ID, 0 to get one assigned.
    'My key',                  # Label for the object.
    1,                         # Domain(s) for the object.
    CAPABILITY.SIGN_ECDSA,     # Capabilities for the ojbect.
    ALGORITHM.EC_K256          # Algorithm for the key.
)

# key = session.get_object(0xc529, OBJECT.ASYMMETRIC_KEY)


def sign_ecdsa(data, hash: hash = hashlib.sha3_256()):
    """Sign data using ECDSA.

    :param bytes data: The data to sign.
    :param hash: (optional) The algorithm to use when hashing the data.
    :return: The resulting signature.
    :rtype: bytes
    """
    hash.update(data)
    data = hash.digest()
    length = hash.digest_size

    msg = struct.pack('!H%ds' % length, key.id, data.rjust(length, b'\0'))
    return session.send_secure_cmd(COMMAND.SIGN_ECDSA, msg)

# Sign some data:
print("******************************************\n\n")
signature = sign_ecdsa(origin_data)  # Create a signature.
print("\n===================================================")
print(f"signature: {signature}")
print("===================================================")
secp256k1_key = PrivateKey()
deserialized_sig = secp256k1_key.ecdsa_deserialize(signature)
print(f"deserialized_sig: {bytes(deserialized_sig.data)}")
print("===================================================")

_public_key = key.get_public_key()

hash_algorithm = hashes.SHA256()
hash_algorithm = asymmetric.utils.Prehashed(hash_algorithm)
try:
    _public_key.verify(signature, hashed_origin_data, ec.ECDSA(hash_algorithm))
    print(f"Succeed to verify first.")
except InvalidSignature:
    print(f"Fail to verify. Invalid Signature.")

der_pub = _public_key.public_bytes(encoding=serialization.Encoding.DER,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
key_info = keys.PublicKeyInfo.load(der_pub)
native_pub = key_info['public_key'].native
print(f"native_pub: {native_pub}")
print("===================================================")
# convert type of public key from EllipticCurvePublicKey to PublickKey(secp256k1)
raw_pubkey_of_pair = PublicKey().deserialize(native_pub)
public_key = PublicKey(raw_pubkey_of_pair)
print(f"serialized pub: {bytes(public_key.serialize(False))}")
print("\n===================================================")
is_verified = public_key.ecdsa_verify(origin_data, deserialized_sig, False, hashlib.sha3_256)
print(f"is_verified: {is_verified}")
print("\n===================================================")

key.delete()
print("Deleted new key.")
# remove_unnecessary_keys(session)

# Clean up
session.close()
hsm.close()

