# Coding: UTF-8

#--------------------------
# Common Value
#--------------------------
content_type_22 = b'\x16'
content_handshake_type_20 = b'\x14'
content_type_23 = b'\x17'
tls_version_12 = b'\x03\x03'
str_64bit = '016x'
sequence_numbers = 0
message_authentication_code_tag_length = 16

#--------------------------
# ServerHello Value
#--------------------------
aes_key_length = 16
initialization_vector_length = 12
hash_length = 32
salt_value = b'\x00'
input_key_material = salt_value * 32
hashtype = "sha256"
derived_bytes = b'derived'
emptiness_bytes = b''
client_handshake_traffic_bytes = b'c hs traffic'
server_handshake_traffic_bytes = b's hs traffic'
key_bytes = b'key'
initialization_vector_bytes = b'iv'
finished_bytes = b'finished'
client_application_traffic_bytes = b'c ap traffic'
server_application_traffic_bytes = b's ap traffic'
export_master_bytes = b'exp master'
content_type_20 = b'\x16'
header_content_type_change_cipher_spec_20 = b'\x14'
dummy_value = b'\x00\x01\01'

#--------------------------
# NewSession Value
#--------------------------
resumption_session_bytes =b'res master' 
resumption_bytes = b'resumption'

#--------------------------
# Alert Value
#--------------------------
content_type_21 = b'\x15'