from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from yubihsm import YubiHsm
from yubihsm.defs import CAPABILITY, ALGORITHM
from yubihsm.objects import YhsmObject, AsymmetricKey

# Connect to the YubiHSM via the connector using the default password:
hsm = YubiHsm.connect('http://localhost:12345')
session = hsm.create_session_derived(1, 'password')

# Generate key externally
ec_key = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())
AsymmetricKey.put(
    session,
    0,
    "test_key_import",
    0xffff,
    CAPABILITY.SIGN_EDDSA | CAPABILITY.EXPORTABLE_UNDER_WRAP,
    ec_key
)

# Get
public_key = ec_key.public_key()

# Delete test object
obj_list = session.list_objects()
obj: YhsmObject = None

for obj in obj_list:
    if obj.get_info().label == "test_key_import":
        print(f"Deleted obj: {obj.get_info()}")
        obj.delete()
    else:
        print(f"Remained obj: {obj.get_info()}")

# Clean up
session.close()
hsm.close()
