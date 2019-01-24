import hashlib

from secp256k1 import PrivateKey, PublicKey, ffi

origin_data = b'Hello world!'
secp256k1_key = PrivateKey()

# # ######################################
# # # TRY TO RECOVER RECOVERABLE SIGNATURE
# # ######################################
# signature = secp256k1_key.ecdsa_sign_recoverable(origin_data, False, hashlib.sha3_256)
# serialized_sig = secp256k1_key.ecdsa_recoverable_serialize(signature)
# print(f"serialized_sig : {serialized_sig}")
# signature = b''.join([serialized_sig[0], bytes([serialized_sig[1]])])
# print(f"full signature : {signature}")
# print(f"\n=============recovery=============\n")
# origin_signature, recover_code = signature[:-1], signature[-1]
# print(f"origin_signature/recover id : {origin_signature}////////////////{recover_code}")
# deserialized_sig = secp256k1_key.ecdsa_recoverable_deserialize(origin_signature, recover_code)
# print(f"deserialized_sig : {deserialized_sig}")
# raw_pub = secp256k1_key.ecdsa_recover(origin_data,
#                                   recover_sig=deserialized_sig,
#                                   raw=False,
#                                   digest=hashlib.sha3_256)
# print(f"serialized raw_pub : {PublicKey(raw_pub).serialize(compressed=False)}")
# print(f"serialized pubkey : {secp256k1_key.pubkey.serialize(compressed=False)}")
# print(f"{secp256k1_key.pubkey.serialize(compressed=False) == PublicKey(raw_pub).serialize(compressed=False)}")

# #################################
# # TRY TO RECOVER NORMAL SIGNATURE
# #################################
signature = secp256k1_key.ecdsa_sign(origin_data, False, hashlib.sha3_256)
print(f"signature: {bytes(signature.data)}")
serialized_sig = secp256k1_key.ecdsa_serialize(signature)
print(f"serialized_sig: {serialized_sig}")

print(f"\n=============recovery=============\n")

deserialized_sig = secp256k1_key.ecdsa_deserialize(serialized_sig)
print(f"deserialized_sig: {bytes(deserialized_sig.data)}")

for i in range(4):
    recover_sig = ffi.new('secp256k1_ecdsa_recoverable_signature *')
    for j in range(len(bytes(deserialized_sig.data))):
        recover_sig.data[j] = deserialized_sig.data[j]

    recover_sig.data[64] = i
    recoverable_serialized_sig = secp256k1_key.ecdsa_recoverable_serialize(recover_sig)
    print(f"recoverable_serialized_sig: {recoverable_serialized_sig}/{type(recoverable_serialized_sig)}")
    recoverable_sig = secp256k1_key.ecdsa_recoverable_deserialize(recoverable_serialized_sig[0], i)
    print(f"recoverable_sig: {bytes(recoverable_sig.data)}")

    try:
        raw_pub = secp256k1_key.ecdsa_recover(origin_data, recoverable_sig, False, hashlib.sha3_256)
        recovered_pub = PublicKey(raw_pub)
        serialized_pub = recovered_pub.serialize(compressed=False)
        origin = secp256k1_key.pubkey.serialize(compressed=False)
        print(f"origin: {origin}")
        print(f"derived: {serialized_pub}")
        is_same = origin == serialized_pub
        if is_same:
            print(f"^^^^^^^^^^^^^^^^^^^^^SUCCESS^^^^^^^^^^^^^^^^^^^^^")
            print(f"{is_same}")
            print(f"signature is verified by RECOVERED pub ? :"
                  f" {recovered_pub.ecdsa_verify(origin_data, deserialized_sig, False, hashlib.sha3_256)}")
            print(f"signature is verified by ORIGINE pub ? :"
                  f" {secp256k1_key.pubkey.ecdsa_verify(origin_data, deserialized_sig, False, hashlib.sha3_256)}")
            print(f"^^^^^^^^^^^^^^^^^^^^^SUCCESS^^^^^^^^^^^^^^^^^^^^^\n")
    except Exception as e:
        print(f"{e}")
