# Coding: UTF-8

# a2b_hex, b2a_hex:https://qiita.com/atsaki/items/6120cad2e3c448d774bf
# curve25519:https://gist.github.com/nickovs/cc3c22d15f239a2640c185035c06f8a3
# scapy.layers.tls.handshake Module: https://github.com/secdev/scapy/blob/master/scapy/layers/tls/handshake.py
# scapy.layers.tls.handshake Module: https://scapy.readthedocs.io/en/latest/api/scapy.layers.tls.handshake.html#
from binascii import a2b_hex
from scapy.layers.tls.handshake import *
from scapy.layers.tls.record_tls13 import *
from ..subfunction import curve25519, functionkit
from . import variables

# =================================
# Main Function
# =================================
# https://datatracker.ietf.org/doc/html/rfc8448#section-3
# replace:https://note.nkmk.me/python-str-replace-translate-re-sub/#replace
# clamp:
# 3. Simple 1-RTT Handshake
#---------------------------------------------------
# Client Create an Ephemeral X25519 Key Pair
#---------------------------------------------------
def create_client_hello(client_private_key_value, client_message_value):
    client_private_key = functionkit.substitution(client_private_key_value)
    client_private_key_length = len(client_private_key) // 2
    curve25519_clamp_value = curve25519.clamp(curve25519.decode_scalar25519(a2b_hex(client_private_key)))
    client_curve25519_X25519_value = curve25519.x25519(curve25519_clamp_value, 9)
    client_public_key = client_curve25519_X25519_value.to_bytes(client_private_key_length, "little")
    client_public_key_int = int.from_bytes(client_public_key, 'little')
#-------------------------------------------------------
# Client Construct a ClientHello Handshake Message
#-------------------------------------------------------
    client_message = a2b_hex(functionkit.substitution(client_message_value))
#-----------------------------------
# Client Send Handshake Record
#-----------------------------------
    Client_hello_record_header = variables.content_type_22 + variables.tls_version_10 + len(client_message).to_bytes(2, 'big')
    Client_hello_record = Client_hello_record_header + client_message
    
    return Client_hello_record