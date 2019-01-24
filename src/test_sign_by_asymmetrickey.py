from cryptography.hazmat.primitives import serialization
from yubihsm import YubiHsm
from yubihsm.defs import CAPABILITY, ALGORITHM
from yubihsm.objects import AsymmetricKey

# Connect to the YubiHSM via the connector using the default password:
hsm = YubiHsm.connect('http://localhost:12345')
session = hsm.create_session_derived(1, 'password')
session.list_objects()
# Generate a private key on the YubiHSM for creating signatures:
key = AsymmetricKey.generate(  # Generate a new key object in the YubiHSM.
    session,                   # Secure YubiHsm session to use.
    0,                         # Object ID, 0 to get one assigned.
    'My key',                  # Label for the object.
    1,                         # Domain(s) for the object.
    CAPABILITY.SIGN_ECDSA,     # Capabilities for the ojbect.
    ALGORITHM.EC_K256          # Algorithm for the key.
)

# serialized_pub_key is a cryptography.io ec.PublicKey, see https://cryptography.io
pub_key = key.get_public_key()

# Write the public key to a file:
with open('public_key.pem', 'w') as f:
    contents = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    f.write(contents.decode())

# Sign some data:
signature = key.sign_ecdsa(b'Hello world!')  # Create a signature.
print(str(signature))
key.delete()

# Clean up
session.close()
hsm.close()
