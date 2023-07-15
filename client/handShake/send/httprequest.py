# Coding: UTF-8

# a2b_hex, b2a_hex:https://qiita.com/atsaki/items/6120cad2e3c448d774bf
# curve25519:https://gist.github.com/nickovs/cc3c22d15f239a2640c185035c06f8a3
from scapy.layers.tls.handshake import SupDataEntry
from scapy.layers.tls.record_tls13 import TLS
from . import variables, parameter
from ..subfunction import functionkit

# =================================
# Main Function
# =================================
def send_http_request_data(application_data, aes_application_key_iv_list):

#-------------------------------------------
# aes_application_key_iv_list Extraction
#-------------------------------------------
	client_write_key_applicatoin = aes_application_key_iv_list[0]
	client_application_initialization_vector = aes_application_key_iv_list[1]
	server_write_key_applicatoin = aes_application_key_iv_list[2]
	server_application_initialization_vector = aes_application_key_iv_list[3]
#-----------------------------
# Application Data Record
#-----------------------------
	server_application_len = len(application_data)
	server_application_type = TLS(application_data).type.to_bytes(1, 'big')
	server_application_version = TLS(application_data).version.to_bytes(2, 'big')
	server_application_tls_packet_length = TLS(application_data).len.to_bytes(2, 'big')
	server_encryption_data = application_data[len(server_application_type + server_application_version + server_application_tls_packet_length):server_application_len]
#---------------------------------
# decryption New Session Data
#---------------------------------
	server_ciphertext = server_encryption_data[0:(len(server_encryption_data) - variables.message_authentication_code_tag_length)]
	server_tag = server_encryption_data[(len(server_encryption_data) - variables.message_authentication_code_tag_length):len(server_encryption_data)]
	decryption_data = functionkit.decryption(server_write_key_applicatoin, server_application_initialization_vector, server_ciphertext, server_tag)
	server_newsession_data = decryption_data[0:(SupDataEntry(decryption_data).len + 4)]
#---------------------------------------
# Client Send Application Data Record
#---------------------------------------
	tls_record_header = variables.content_type_23 + variables.tls_version_12 + (len(parameter.tls_payload) + 1 + variables.message_authentication_code_tag_length).to_bytes(2, 'big')
	application_record = functionkit.encryption(client_write_key_applicatoin, client_application_initialization_vector, parameter.tls_payload, variables.content_type_23, tls_record_header)
	
	return application_record