# Coding: UTF-8

from binascii import a2b_hex
from ..send import variables
from Crypto.Cipher import AES

#------------------------
# Substitution String
#------------------------
def substitution(raw_data):
	substitution_value = raw_data.replace(" ", "")
	return substitution_value

#--------------------------------
# AES Initialization Vector
#--------------------------------
def aes_initialization_vector(sequence_numbers, client_x25519, server_x25519, write_initialization_vector_handshake):
	sequence_numbers = a2b_hex(substitution(format(sequence_numbers, variables.str_64bit)))
	padded_sequence_number = b'\x00' * (variables.initialization_vector_length - len(sequence_numbers)) + sequence_numbers
	aes_initialization_vector_value = bytes([client_x25519 ^ server_x25519 for client_x25519, server_x25519 in zip(padded_sequence_number, write_initialization_vector_handshake)])
	return aes_initialization_vector_value

#--------------------------------
# AES Encryption
#--------------------------------
def encryption(write_key_handshake, initialization_vector, tls_payload, content_type, tls_record_header):
	cipher = AES.new(write_key_handshake, AES.MODE_GCM, initialization_vector)
	#cipher.update(tls_record_header)
	ciphertext, tag = cipher.encrypt_and_digest(tls_payload + content_type)
	handshake_record = tls_record_header + (ciphertext + tag)
	return handshake_record

#--------------------------------
# AES Decryption
#--------------------------------
def decryption(write_key_handshake, initialization_vector, ciphertext, tag):
	cipher = AES.new(write_key_handshake, AES.MODE_GCM, initialization_vector)
	decryption_data = cipher.decrypt_and_verify(ciphertext, tag)
	return decryption_data