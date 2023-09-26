import pickle, os
import ecdsa, hashlib

DEFAULT_TARGET = "./keypair.pem"

class SECP256k1:
    def __init__(self, target=DEFAULT_TARGET):
        self.target = target
    def store(self, data):
        with open(self.target, 'wb') as f:
            pickle.dump(data, f)
    def load(self):
        with open(self.target, 'rb') as f:
            data = pickle.load(f)
            return {
                "private_key": data["private_key"],
                "public_key_x": data["public_key_x"],
                "public_key_y": data["public_key_y"],
                "public_key_hex": data["public_key_hex"]
            }
    def new(self):
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()
        public_key_hex_uncompressed = public_key.to_string("uncompressed").hex()
        x_coordinate_bytes = list(bytes.fromhex(public_key_hex_uncompressed)[1:33])
        y_coordinate_bytes = list(bytes.fromhex(public_key_hex_uncompressed)[33:])

        return {
            "private_key": private_key,
            "public_key_x": x_coordinate_bytes,
            "public_key_y": y_coordinate_bytes,
            "public_key_hex": public_key_hex_uncompressed
        }
    def sign(self, message):
        data = self.load()
        private_key = data["private_key"]
        # hash the message and sign the hash
        message_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
        message_bytes = bytes.fromhex(message_hash)
        signature = private_key.sign_deterministic(
            message_bytes, 
            extra_entropy=b"",
            # hash the message hash (2x sha256)
            hashfunc=hashlib.sha256
        )
        return {
            "message": message_bytes,
            "signature": signature
        }
    def sign_and_print(self, message):
        data = self.sign(message)
        print("Message: ", list(data["message"]))
        print("Signature: ", list(bytes.fromhex(data["signature"].hex())))
        keys = self.load()
        print("X coordinate: ", keys["public_key_x"])
        print("Y coordinate: ", keys["public_key_y"])
        print("Hex Public: ", keys["public_key_hex"])
'''
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
'''

if not os.path.exists(DEFAULT_TARGET):
    open(DEFAULT_TARGET, 'x')
secp = SECP256k1()
# create new keypair and save at DEFAULT_TARGET
secp.store(secp.new())
# sign an oversimplified transaction
secp.sign_and_print("jonas10")


# Output:
'''
Message:  [223, 188, 58, 84, 128, 209, 132, 159, 182, 174, 107, 205, 234, 148, 208, 98, 10, 244, 95, 54, 104, 102, 222, 247, 5, 178, 215, 155, 140, 244, 23, 221]

Signature:  [231, 122, 163, 143, 93, 12, 18, 132, 138, 215, 111, 46, 67, 202, 74, 30, 1, 182, 92, 92, 81, 117, 227, 209, 150, 177, 116, 185, 27, 220, 170, 134, 32, 74, 210,
    119, 169, 78, 210, 35, 203, 151, 209, 89, 232, 67, 39, 113, 78, 155, 34, 147, 86, 152, 75, 154, 158, 220, 35, 12, 255, 18, 23, 103]

X coordinate:  [57, 141, 121, 60, 115, 189, 115, 103, 174, 6, 108, 20, 114, 134, 156, 80, 7, 222, 7, 107, 196, 2, 216, 251, 119, 174, 151, 31, 19, 46, 39, 92]

Y coordinate:  [207, 92, 161, 239, 169, 234, 3, 35, 59, 37, 172, 77, 65, 179, 24, 23, 210, 215, 112, 148, 177, 230, 247, 201, 131, 225, 233, 194, 143, 189, 239, 9]

Hex Public:  04398d793c73bd7367ae066c1472869c5007de076bc402d8fb77ae971f132e275ccf5ca1efa9ea03233b25ac4d41b31817d2d77094b1e6f7c983e1e9c28fbdef09
'''