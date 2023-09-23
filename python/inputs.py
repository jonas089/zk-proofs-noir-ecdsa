import ecdsa, hashlib
# Generate a random private key
private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

# Derive the corresponding public key
public_key = private_key.get_verifying_key()
public_key_hex_uncompressed = public_key.to_string("uncompressed").hex()
# exclude the first (prefix) byte e.g. 04
x_coordinate_bytes = list(bytes.fromhex(public_key_hex_uncompressed)[1:33])
y_coordinate_bytes = list(bytes.fromhex(public_key_hex_uncompressed)[33:])
# Hash the message
message_hash = hashlib.sha256("Hello, World!".encode('utf-8')).hexdigest()

# Convert the message hash (hex) to bytes
message_bytes = bytes.fromhex(message_hash)

# Sign the hashed message using the private key
signature = private_key.sign_deterministic(
    message_bytes, 
    extra_entropy=b"",
    # hash the message hash (2x sha256)
    hashfunc=hashlib.sha256
)
# print the message input (32 bytes)
print("message_bytes: ", list(message_bytes))
# print the x coordinate (32 bytes)
print("x_coordinate: ", x_coordinate_bytes)
# print the y coordinate (32 bytes)
print("y_coordinate: ", y_coordinate_bytes)
# print the Signature (64 bytes)
print("signature: ", list(bytes.fromhex(signature.hex())))