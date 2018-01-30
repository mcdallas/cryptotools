import rsa

private, public = rsa.generate_keypair(512)

txt = 'deadbeef'
message = rsa.Message.from_hex(txt)

message.encrypt(public)
message.decrypt(private)
assert message == rsa.Message.from_hex(txt)

message.encrypt(private)
message.decrypt(public)
assert message == rsa.Message.from_hex(txt)

message = rsa.Message.from_str('kinakuta')
signature = message.sign(private)
assert message.verify(signature, public)

print('It works!')
