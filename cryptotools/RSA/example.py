from cryptotools import RSA

private, public = RSA.generate_keypair(512)

txt = 'deadbeef'
message = RSA.Message.from_hex(txt)

message.encrypt(public)
message.decrypt(private)
assert message == RSA.Message.from_hex(txt)

message.encrypt(private)
message.decrypt(public)
assert message == RSA.Message.from_hex(txt)

message = RSA.Message.from_str('kinakuta')
signature = message.sign(private)
assert message.verify(signature, public)

# print('It works!')
