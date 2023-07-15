#UTF-8 Coding

from binascii import a2b_hex
from scapy.layers.tls.record import TLS, TLSAlert
from . import variables, parameter
from ..subfunction import functionkit

# =================================
# Main Processing
# =================================
def alert(receive_alert, encryption_applicationdata_kit):

#---------------------------------------------
# encryption_applicationdata_kit Extraction
#---------------------------------------------
	client_write_key_application = encryption_applicationdata_kit[0]
	client_write_initialization_vector_applicatoin = encryption_applicationdata_kit[1]
	server_write_key_application = encryption_applicationdata_kit[2]
	server_write_initialization_vector_application = encryption_applicationdata_kit[3]
	client_curve25519_X25519 = encryption_applicationdata_kit[4]
	server_curve25519_X25519 = encryption_applicationdata_kit[5]
#-----------------------------
# Alert Record
#-----------------------------
	client_application_len = len(receive_alert)
	client_application_type = TLS(receive_alert).type.to_bytes(1, 'big')
	client_application_version = TLS(receive_alert).version.to_bytes(2, 'big')
	client_application_tls_packet_length = TLS(receive_alert).len.to_bytes(2, 'big')
	client_encryption_data = receive_alert[len(client_application_type + client_application_version + client_application_tls_packet_length):client_application_len]
#--------------------------------------
# decryption Alert
#--------------------------------------
	client_application_initialization_vector = functionkit.aes_initialization_vector((variables.sequence_numbers + 1), client_curve25519_X25519, client_curve25519_X25519, client_write_initialization_vector_applicatoin)
	client_ciphertext = client_encryption_data[0:(len(client_encryption_data) - variables.message_authentication_code_tag_length)]
	client_tag = client_encryption_data[(len(client_encryption_data) - variables.message_authentication_code_tag_length):len(client_encryption_data)]
	decryption_data = functionkit.decryption(client_write_key_application, client_application_initialization_vector, client_ciphertext, client_tag)
	alert_data = decryption_data[0:(len(decryption_data) - len(TLSAlert(decryption_data).load))]
#--------------------------------------
# Send Alert Record
#--------------------------------------
	alert_payload = a2b_hex(parameter.alert_payload)
	tls_record_header = variables.content_type_23 + variables.tls_version_12 + (len(alert_payload) + 1 + variables.message_authentication_code_tag_length).to_bytes(2, 'big')
	server_application_initialization_vector = functionkit.aes_initialization_vector((variables.sequence_numbers + 2), client_curve25519_X25519, server_curve25519_X25519, server_write_initialization_vector_application)
	handshake_record = functionkit.encryption(server_write_key_application, server_application_initialization_vector, alert_payload, variables.content_type_21, tls_record_header)
	
	return handshake_record