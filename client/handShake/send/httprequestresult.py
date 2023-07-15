# UTF-8 Coding

from binascii import a2b_hex
from scapy.layers.tls.handshake import SupDataEntry
from scapy.layers.tls.record_tls13 import TLS
from ..subfunction import functionkit
from . import variables, parameter

# =================================
# Main Processing
# =================================
def http_response_data(receive_http_response, aes_write_application_list, curve25519_X25519_list):

#---------------------------------------------
# aes_application_key_iv_list Extraction
#---------------------------------------------
	client_write_key_applicatoin = aes_write_application_list[0]
	client_write_initialization_vector_applicatoin = aes_write_application_list[1]
	server_write_key_applicatoin = aes_write_application_list[2]
	server_write_initialization_vector_applicatoin = aes_write_application_list[3]
#---------------------------------------------
# curve25519_X25519_list Extraction
#---------------------------------------------
	client_curve25519_x25519 = curve25519_X25519_list[0]
	server_curve25519_x25519 = curve25519_X25519_list[1]
#-----------------------------
# Application Data Record
#-----------------------------
	server_application_len = len(receive_http_response)
	server_application_type = TLS(receive_http_response).type.to_bytes(1, 'big')
	server_application_version = TLS(receive_http_response).version.to_bytes(2, 'big')
	server_application_tls_packet_length = TLS(receive_http_response).len.to_bytes(2, 'big')
	server_encryption_data = receive_http_response[len(server_application_type + server_application_version + server_application_tls_packet_length):server_application_len]
#--------------------------------------
# decryption HTTP Response Data
#--------------------------------------
	server_ciphertext = server_encryption_data[0:(len(server_encryption_data) - variables.message_authentication_code_tag_length)]
	server_tag = server_encryption_data[(len(server_encryption_data) - variables.message_authentication_code_tag_length):len(server_encryption_data)]
	server_application_initialization_vector = functionkit.aes_initialization_vector((variables.sequence_numbers + 1), client_curve25519_x25519, server_curve25519_x25519, server_write_initialization_vector_applicatoin)
	decryption_data = functionkit.decryption(server_write_key_applicatoin, server_application_initialization_vector, server_ciphertext, server_tag)
	http_response_data = decryption_data[0:(SupDataEntry(decryption_data).len + 4)]
	http_response_data = str(http_response_data, 'UTF-8')
	print(http_response_data)
#--------------------------------------
# Send Alert Record
#--------------------------------------
	alert_payload = a2b_hex(parameter.alert_payload)
	tls_record_header = variables.content_type_23 + variables.tls_version_12 + (len(alert_payload) + 1 + variables.message_authentication_code_tag_length).to_bytes(2, 'big')
	client_application_initialization_vector = functionkit.aes_initialization_vector((variables.sequence_numbers + 1), client_curve25519_x25519, server_curve25519_x25519, client_write_initialization_vector_applicatoin)
	handshake_record = functionkit.encryption(client_write_key_applicatoin, client_application_initialization_vector, alert_payload, variables.content_type_21, tls_record_header)
	
	return handshake_record