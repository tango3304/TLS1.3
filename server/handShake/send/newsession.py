# UTF-8 Coding

from binascii import a2b_hex, hexlify
from scapy.layers.tls.handshake import SupDataEntry
from scapy.layers.tls.record_tls13 import TLS
from ..subfunction import hkdf, functionkit
from . import variables, parameter

# =================================
# Main Function
# =================================
def new_session_ticket(client_send_data, inherting_list):

#-------------------------------
# inherting_list Selection
#-------------------------------
	session_messages = inherting_list[0]
	master_secret = inherting_list[1]
	hashtype = inherting_list[2]
	hash_length = inherting_list[3]
	server_write_key_handshake = inherting_list[4]
	client_write_key_handshake = inherting_list[5]
	server_handshake_initialization_vector = inherting_list[6]
	client_handshake_initialization_vector = inherting_list[7]
	server_application_initialization_vector = inherting_list[8]
	server_write_key_application = inherting_list[9]
#--------------------------------------------------
# Client CipheText and Client Tag 
#--------------------------------------------------
	record_header_type = TLS(client_send_data).type.to_bytes(1, 'big')
	record_header_version = TLS(client_send_data).version.to_bytes(2, 'big')
	record_header_len = TLS(client_send_data).len.to_bytes(2, 'big')
	record_header = record_header_type + record_header_version + record_header_len
	client_aead_encrypted = a2b_hex((hexlify(client_send_data).decode('UTF-8').replace(hexlify(record_header).decode('UTF-8'), "")).encode('UTF-8'))
	client_ciphertext = client_aead_encrypted[0:(len(client_aead_encrypted) - variables.message_authentication_code_tag_length)]
	client_tag = client_aead_encrypted[(len(client_aead_encrypted) - variables.message_authentication_code_tag_length):len(client_aead_encrypted)]
#-------------------------------
# decryption Client Send Data
#-------------------------------
	decription_data = functionkit.decryption(client_write_key_handshake, client_handshake_initialization_vector, client_ciphertext, client_tag)
	client_finished_len = (SupDataEntry(decription_data).len) + 4
	client_finished = decription_data[0:client_finished_len]
#--------------------------------------------------
# Generate Resumption Secret "tls13 resumption"
#--------------------------------------------------
	session_messages.append(client_finished)
	resumption_session = hkdf.derive_secret(master_secret, variables.resumption_session_bytes, session_messages, hashtype)
	resumption_session_secret = hkdf.expand_label(resumption_session, variables.resumption_bytes, b'\x00\x00', hash_length, hashtype)
#--------------------------------------------------
# Construct a NewSessionTicket Handshake Message
#--------------------------------------------------
	new_session_ticket = a2b_hex(functionkit.substitution(parameter.new_session_ticket_value))
	tls_payload = new_session_ticket
#---------------------------------
# Server Send Handshake Record
#---------------------------------
	tls_record_header = variables.content_type_23 + variables.tls_version_12 + (len(new_session_ticket) + 1 + variables.message_authentication_code_tag_length).to_bytes(2, 'big')
	server_handshake_record = functionkit.encryption(server_write_key_application, server_application_initialization_vector, tls_payload, variables.content_type_22, tls_record_header)
	
	return server_handshake_record