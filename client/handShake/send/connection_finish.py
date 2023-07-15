# UTF-8 Coding

from binascii import b2a_hex
from scapy.layers.tls.record import TLS, TLSAlert
from . import variables
from ..subfunction import functionkit

# =================================
# Main Processing
# =================================
def http_response_data(receive_alert_response, aes_write_application_list, curve25519_X25519_list):
#---------------------------------------------
# aes_application_key_iv_list Extraction
#---------------------------------------------
	server_write_key_applicatoin = aes_write_application_list[2]
	server_write_initialization_vector_applicatoin = aes_write_application_list[3]
#---------------------------------------------
# curve25519_X25519_list Extraction
#---------------------------------------------
	client_curve25519_x25519 = curve25519_X25519_list[0]
	server_curve25519_x25519 = curve25519_X25519_list[1]
#-----------------------------
# Alert Record
#-----------------------------
	server_application_len = len(receive_alert_response)
	server_application_type = TLS(receive_alert_response).type.to_bytes(1, 'big')
	server_application_version = TLS(receive_alert_response).version.to_bytes(2, 'big')
	server_application_tls_packet_length = TLS(receive_alert_response).len.to_bytes(2, 'big')
	server_encryption_data = receive_alert_response[len(server_application_type + server_application_version + server_application_tls_packet_length):server_application_len]
#--------------------------------------
# decryption Alert
#--------------------------------------
	server_application_initialization_vector = functionkit.aes_initialization_vector((variables.sequence_numbers + 2), client_curve25519_x25519, server_curve25519_x25519, server_write_initialization_vector_applicatoin)
	server_ciphertext = server_encryption_data[0:(len(server_encryption_data) - variables.message_authentication_code_tag_length)]
	server_tag = server_encryption_data[(len(server_encryption_data) - variables.message_authentication_code_tag_length):len(server_encryption_data)]
	decryption_data = functionkit.decryption(server_write_key_applicatoin, server_application_initialization_vector, server_ciphertext, server_tag)
	alert_record = str(b2a_hex(decryption_data[(len(decryption_data) - len(TLSAlert(decryption_data).load)):len(decryption_data)]), 'iso-8859-1')
	
	return alert_record