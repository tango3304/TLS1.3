# Coding: UTF-8

#--------------------------
# Common Value
#--------------------------
content_type_22 = b'\x16'
content_handshake_type_20 = b'\x14'
content_type_23 = b'\x17'
aes_key_length = 16
initialization_vector_length = 12
hashtype = "sha256"
derived_bytes = b'derived'
emptiness_bytes = b''
finished_bytes = b'finished'
salt_value = b'\x00'
client_handshake_traffic_bytes = b'c hs traffic'
server_handshake_traffic_bytes = b's hs traffic'
client_application_traffic_bytes = b'c ap traffic'
server_application_traffic_bytes = b's ap traffic'
key_bytes = b'key'
initialization_vector_bytes = b'iv'
resumption_session_bytes = b'res master'
message_authentication_code_tag_length = 16
str_64bit = '016x'
sequence_numbers = 0
tls_version_12 = b'\x03\x03'

#--------------------------
# CerverHello Value
#--------------------------
tls_version_10 = b'\x03\x01'
changecipherspec_record = b'\x14\x03\x03\x00\x01\x01'

#------------------------------
# httprequestresult Value
#------------------------------
content_type_21 = b'\x15'