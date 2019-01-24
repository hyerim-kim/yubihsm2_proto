import hashlib

from asn1crypto import keys
from cryptography import utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from secp256k1 import PrivateKey, PublicKey, ffi
from yubihsm import YubiHsm
from yubihsm.defs import CAPABILITY, ALGORITHM
from yubihsm.objects import AsymmetricKey, YhsmObject

# Connect to the YubiHSM via the connector using the default password:


def remove_unnecessary_keys(hsm_session):
    obj_list = hsm_session.list_objects()
    for obj in obj_list:
        if obj.get_info().label == "My key" and obj.get_info().id not in [int(0x3125), int(0x0064), int(0xbc60)]:
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


hsm = YubiHsm.connect('http://localhost:12345')
session = hsm.create_session_derived(1, 'password')
session.list_objects()

origin_data = b'Hello world!'
# Generate a private key on the YubiHSM for creating signatures:
key = AsymmetricKey.generate(  # Generate a new key object in the YubiHSM.
    session,                   # Secure YubiHsm session to use.
    0,                         # Object ID, 0 to get one assigned.
    'My key',                  # Label for the object.
    1,                         # Domain(s) for the object.
    CAPABILITY.SIGN_ECDSA,     # Capabilities for the ojbect.
    ALGORITHM.EC_K256          # Algorithm for the key.
)

# Sign some data:
print("******************************************\n\n")
signature = key.sign_ecdsa(origin_data)  # Create a signature.
print("\n===================================================")
print(f"signature: {signature}")
print("===================================================")

_public_key = key.get_public_key()
der_pub = _public_key.public_bytes(encoding=serialization.Encoding.DER,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)

key_info = keys.PublicKeyInfo.load(der_pub)
native_pub = key_info['public_key'].native

# get pem after converting from EllipticCurvePublicKey to PublickKey(secp256k1)
raw_pubkey_of_pair = PublicKey().deserialize(native_pub)
serialized_pubkey_of_pair = PublicKey(raw_pubkey_of_pair).serialize(compressed=False)
ec_pubkey_of_pair = convert_to_elliptic_curve_publickey(serialized_pubkey_of_pair)
twin_of_pub_key = ec_pubkey_of_pair.public_key(default_backend())
twin_der_pub = twin_of_pub_key.public_bytes(encoding=serialization.Encoding.DER,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
print(f"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxpair_der_pub: {twin_der_pub}")
print(f"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx{twin_der_pub == der_pub}")

print("\n===================================================")
print(f"native_pub: {native_pub}")
print("===================================================")

is_hash = False
secp256k1_key = PrivateKey()
deserialized_sig = secp256k1_key.ecdsa_deserialize(signature)
print(f"deserialized_sig: {bytes(deserialized_sig.data)}")

for i in range(4):
    recover_sig = ffi.new('secp256k1_ecdsa_recoverable_signature *')
    for j in range(len(bytes(deserialized_sig.data))):
        recover_sig.data[j] = deserialized_sig.data[j]

    recover_sig.data[64] = i
    recoverable_serialized_sig = secp256k1_key.ecdsa_recoverable_serialize(recover_sig)
    print(f"recoverable_serialized_sig: {recoverable_serialized_sig}")

    recoverable_sig = secp256k1_key.ecdsa_recoverable_deserialize(recoverable_serialized_sig[0], i)
    print(f"recoverable_sig: {bytes(recoverable_sig.data)}")

    try:
        raw_public_key = secp256k1_key.ecdsa_recover(origin_data, recoverable_sig, is_hash, hashlib.sha3_256)
        pub_key = PublicKey(raw_public_key).serialize(compressed=False)

        print(f"pub_key: \n{pub_key}")
        print(f"origin_pub_key: \n{native_pub}")
        print(f"------------------------{pub_key == native_pub}")

        # convert from recovered PublickKey(secp256k1) to EllipticCurvePublicKey
        pubkey = convert_to_elliptic_curve_publickey(pub_key)
        yubi_pub_key = pubkey.public_key(default_backend())
        yubi_der_pub = yubi_pub_key.public_bytes(encoding=serialization.Encoding.DER,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
        print(f"yubi_pem_pub: {yubi_der_pub}")
        print(f"recovered key pem == origin key pem: {yubi_der_pub == der_pub}")

    except Exception as e:
        print(f"--------------------------------------------------------------------------------------::{e}/{type(e)}")

else:
    print("\n\n******************************************")
    key.delete()
    print("Deleted new key.")
    # remove_unnecessary_keys(session)

# Clean up
session.close()
hsm.close()
