# Coding: UTF-8

# a2b_hex, b2a_hex:https://qiita.com/atsaki/items/6120cad2e3c448d774bf
# curve25519:https://gist.github.com/nickovs/cc3c22d15f239a2640c185035c06f8a3
# scapy.layers.tls.handshake Module: https://github.com/secdev/scapy/blob/master/scapy/layers/tls/handshake.py
# scapy.layers.tls.handshake Module: https://scapy.readthedocs.io/en/latest/api/scapy.layers.tls.handshake.html#
from binascii import a2b_hex, b2a_hex, hexlify
from scapy.layers.tls.handshake import TLSEncryptedExtensions,TLSCertificateVerify,SupDataEntry,TLS13Certificate
from scapy.layers.tls.record_tls13 import TLS
from ..subfunction import curve25519, hkdf, functionkit
from hmac import new
from .parameter import client_private_key_value, client_message_value
from . import variables

# =================================
# Main Processing
# =================================
def create_client_finished(server_record, send_client_hello_record):

#------------------------
# Server Hello Record
#------------------------
	server_record_len = len(server_record)
	server_hello_type = TLS(server_record).type.to_bytes(1, 'big')
	server_hello_version = TLS(server_record).version.to_bytes(2, 'big')
	client_hello_tls_packet_length = TLS(server_record).len.to_bytes(2, 'big')
	server_hello_record_len = TLS(server_record).len
	server_hello_record = server_record[0:(server_hello_record_len + len(server_hello_type + server_hello_version + client_hello_tls_packet_length))]
#----------------------------------------------
# Server Hello Value & Client Hello Value
#----------------------------------------------
	record_header = b2a_hex(server_hello_type + server_hello_version + client_hello_tls_packet_length).decode('UTF-8')
	server_hello_value = a2b_hex(hexlify(server_hello_record).decode('UTF-8').replace(record_header,"").encode('UTF-8'))
	client_hello_value = a2b_hex(functionkit.substitution(client_message_value))
#-------------------------------------------------------
# Server & Client PublicKey AND Curve25519(X25519)
#-------------------------------------------------------
	server_public_key = TLS(server_hello_record).msg[0].ext[0].server_share[0].key_exchange
	server_curve25519_x25519 = int.from_bytes(server_public_key, 'little')
	client_public_key = TLS(send_client_hello_record).msg[0].ext[4].client_shares[0].key_exchange
	client_curve25519_x25519 = int.from_bytes(client_public_key, 'little')
	curve25519_X25519_list = [client_curve25519_x25519, server_curve25519_x25519]
#-------------------------------------------------------
# Key Share Entry Keylength
#-------------------------------------------------------
	kxlen = TLS(server_hello_record).msg[0].ext[0].server_share[0].kxlen
#-----------------------------------
# Client Extract Secret "early"
#-----------------------------------
	input_key_material = variables.salt_value * kxlen
	early_secret = hkdf.extract(variables.salt_value, input_key_material, variables.hashtype)
#----------------------------------------------------------
# Client Derive Secret For Handshake "TLS1.3 derived"
#----------------------------------------------------------
	driver_secret = hkdf.derive_secret(early_secret, variables.derived_bytes, variables.emptiness_bytes, variables.hashtype)
#----------------------------------
# Client ECDH SECRET Create
#----------------------------------
	client_curve25519_clamp = curve25519.clamp(curve25519.decode_scalar25519(a2b_hex(functionkit.substitution(client_private_key_value))))
	client_server_x25519 = curve25519.x25519(client_curve25519_clamp, server_curve25519_x25519)
	client_ecdh_secret = client_server_x25519.to_bytes(kxlen, 'little')
#-------------------------------------
# Client Extract Secret "handshake"
#-------------------------------------
	secret_handshake = hkdf.extract(driver_secret, client_ecdh_secret, variables.hashtype)
#------------------------------------------
# Server & Client Handshake Traffic
#------------------------------------------
	client_handshake_traffic = hkdf.derive_secret(secret_handshake, variables.client_handshake_traffic_bytes, [client_hello_value, server_hello_value], variables.hashtype)
	server_handshake_traffic = hkdf.derive_secret(secret_handshake, variables.server_handshake_traffic_bytes, [client_hello_value, server_hello_value], variables.hashtype)
#-----------------------------------------------------
# Client Derive Secret For Master "TLS1.3 derived"
#-----------------------------------------------------
	master_secret_location = hkdf.derive_secret(secret_handshake, variables.derived_bytes, variables.emptiness_bytes, variables.hashtype)
#---------------------------------
# Client Extract Secret "master"
#---------------------------------
	master_secret = hkdf.extract(master_secret_location, input_key_material, variables.hashtype)
#-----------------------------------------------------------
# Client Derive Write Traffic Keys For Handshake Data
#-----------------------------------------------------------
	server_write_key_handshake = hkdf.expand_label(server_handshake_traffic, variables.key_bytes, variables.emptiness_bytes, variables.aes_key_length, variables.hashtype)
	server_write_initialization_vector_handshake = hkdf.expand_label(server_handshake_traffic, variables.initialization_vector_bytes, variables.emptiness_bytes, variables.initialization_vector_length, variables.hashtype)
#-----------------------------
# Change Cipher Spec Record
#-----------------------------
	server_record_tmp = server_record[len(server_hello_record):server_record_len]
	changecipherspec_record_str = hexlify(variables.changecipherspec_record).decode('UTF-8')
#-----------------------------
# Create Server Nonce(GCM)
#-----------------------------
	server_handshake_initialization_vector = functionkit.aes_initialization_vector(variables.sequence_numbers, client_curve25519_x25519, server_curve25519_x25519, server_write_initialization_vector_handshake)
#------------------------
# Application Data Record
#------------------------
	application_data_encryption = a2b_hex((hexlify(server_record_tmp).decode('UTF-8').replace(changecipherspec_record_str, "")).encode('UTF-8'))
	application_data_type = TLS(application_data_encryption).type.to_bytes(1, 'big')
	application_data_version = TLS(application_data_encryption).version.to_bytes(2, 'big')
	application_data_tls_packet_length = TLS(application_data_encryption).len.to_bytes(2, 'big')
	application_data_header_length = len(application_data_type + application_data_version + application_data_tls_packet_length)
	application_data_record_len = len(application_data_encryption)
	application_data_record = application_data_encryption[application_data_header_length:application_data_record_len]
#-------------------------------
# Application Data Decryption
#-------------------------------
	server_ciphertext = application_data_record[0:(len(application_data_record) - variables.message_authentication_code_tag_length)]
	server_tag = application_data_record[(len(application_data_record) - variables.message_authentication_code_tag_length):len(application_data_record)]
	decryption_data = functionkit.decryption(server_write_key_handshake, server_handshake_initialization_vector, server_ciphertext, server_tag)
	decryption_data_len = len(decryption_data)
#-----------------------
# Encrypted Extensions
#-----------------------
	encrypted_extensions_len = (TLSEncryptedExtensions(decryption_data).msglen) + 4
	encrypted_extensions = decryption_data[0:encrypted_extensions_len]
#---------------
# Certificate
#---------------
	decryption_data_tmp = decryption_data[encrypted_extensions_len:decryption_data_len]
	certificate_len = (TLS13Certificate(decryption_data_tmp).msglen) + 4
	certificate = decryption_data_tmp[0:certificate_len]
#-----------------------
# CertificateVerify
#-----------------------
	decryption_data_tmp = decryption_data[(encrypted_extensions_len + certificate_len):decryption_data_len]
	certificate_verify_len = (TLSCertificateVerify(decryption_data_tmp).msglen) + 4
	certificate_verify = decryption_data_tmp[0:certificate_verify_len]
#-----------------------
# Server Finished
#-----------------------
	decryption_data_tmp = decryption_data[(encrypted_extensions_len + certificate_len + certificate_verify_len):decryption_data_len]
	server_finished_len = (SupDataEntry(decryption_data_tmp).len) + 4
	server_finished = decryption_data_tmp[0:server_finished_len]
#--------------------------------------------------
# Client Calculate Finished "tls13 finished"
#--------------------------------------------------
	client_finished_key = hkdf.expand_label(client_handshake_traffic, variables.finished_bytes, variables.emptiness_bytes, kxlen, variables.hashtype)
	messages = [client_hello_value, server_hello_value, encrypted_extensions, certificate, certificate_verify, server_finished]
	client_verify_data = new(client_finished_key, hkdf.transcript_hash(messages, variables.hashtype), variables.hashtype).digest()
#--------------------------------------------------
# Client Construct a Finished Handshake Message
#--------------------------------------------------
	client_finished = variables.content_handshake_type_20 + len(client_verify_data).to_bytes(3, 'big') + client_verify_data
#---------------------------------
# Client Send Handshake Record
#---------------------------------
	client_payload = client_finished
	tls_record_header = variables.content_type_23 + variables.tls_version_12 + (len(client_payload) + 1 + variables.message_authentication_code_tag_length).to_bytes(2, 'big')
#---------------------------------------------
# Client Send Handshake Data Key
#---------------------------------------------
	client_write_key_handshake = hkdf.expand_label(client_handshake_traffic, variables.key_bytes, variables.emptiness_bytes, variables.aes_key_length, variables.hashtype)
	client_write_initialization_vector_handshake = hkdf.expand_label(client_handshake_traffic, variables.initialization_vector_bytes, variables.emptiness_bytes, variables.initialization_vector_length, variables.hashtype)
#-------------------------------
# Create Client Nonce(GCM)
#-------------------------------
	client_handshake_initialization_vector = functionkit.aes_initialization_vector(variables.sequence_numbers, client_curve25519_x25519, server_curve25519_x25519, client_write_initialization_vector_handshake)
#-------------------------------
# Application Data Encryption
#-------------------------------
	handshake_record = functionkit.encryption(client_write_key_handshake, client_handshake_initialization_vector, client_payload, variables.content_type_22, tls_record_header)
#---------------------------------------------------------------------
# Client Application Data Eecryption Key and Initialization Vector
#---------------------------------------------------------------------
	client_application_key_location = hkdf.derive_secret(master_secret, variables.client_application_traffic_bytes, messages, variables.hashtype)
	client_write_key_applicatoin = hkdf.expand_label(client_application_key_location, variables.key_bytes, variables.emptiness_bytes, variables.aes_key_length, variables.hashtype)
	client_write_initialization_vector_applicatoin = hkdf.expand_label(client_application_key_location, variables.initialization_vector_bytes, variables.emptiness_bytes, variables.initialization_vector_length, variables.hashtype)
#---------------------------------------------------------------------
# server Application Data Eecryption Key and Initialization Vector
#---------------------------------------------------------------------
	server_application_key_location = hkdf.derive_secret(master_secret, variables.server_application_traffic_bytes, messages, variables.hashtype)
	server_write_key_applicatoin = hkdf.expand_label(server_application_key_location, variables.key_bytes, variables.emptiness_bytes, variables.aes_key_length, variables.hashtype)
	server_write_initialization_vector_applicatoin = hkdf.expand_label(server_application_key_location, variables.initialization_vector_bytes, variables.emptiness_bytes, variables.initialization_vector_length, variables.hashtype)
	aes_write_application_list = [client_write_key_applicatoin, client_write_initialization_vector_applicatoin, server_write_key_applicatoin, server_write_initialization_vector_applicatoin]
#--------------------------------------------------------
# derive secret "tls13 res master" (Session Restart)
#--------------------------------------------------------
	session_messages = [client_hello_value, server_hello_value, encrypted_extensions, certificate, certificate_verify, server_finished, client_finished]
	resumption_session = hkdf.derive_secret(master_secret, variables.resumption_session_bytes, session_messages, variables.hashtype)

	return handshake_record, aes_write_application_list, curve25519_X25519_list