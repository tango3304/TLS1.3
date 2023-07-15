# Coding: UTF-8

from binascii import a2b_hex, hexlify
from scapy.layers.tls.handshake import *
from scapy.layers.tls.record_tls13 import *
from hmac import new
from hashlib import sha256
from ..subfunction import curve25519, hkdf, functionkit
from . import variables, parameter


# https://datatracker.ietf.org/doc/html/rfc5116#section-5.1
# https://tex2e.github.io/blog/protocol/quic-initial-packet-decrypt
# iv_length,message_authentication_code_tag_length:https://www.ibm.com/docs/de/linux-on-systems?topic=functions-ica-aes-gcm
# 5.1.  AEAD_AES_128_GCM
#=================================
# Main Function
#=================================
def server_hello_function(client_hello_record):

#-----------------------
# Setting Parameter
#-----------------------
	client_hello_type = TLS(client_hello_record).type.to_bytes(1, 'big')
	client_hello_version = TLS(client_hello_record).version.to_bytes(2, 'big')
	client_hello_tls_packet_length = TLS(client_hello_record).len.to_bytes(2, 'big')
	client_hello_key_exchange = hexlify(TLS(client_hello_record).msg[0].ext[4].client_shares[0].key_exchange)
	client_hello_key_exchange_hexadecimal = TLS(client_hello_record).msg[0].ext[4].client_shares[0].key_exchange

	client_curve25519_X25519 = int.from_bytes(client_hello_key_exchange_hexadecimal, 'little')
	client_hello_value = (hexlify(client_hello_record).decode('UTF-8').replace(hexlify(client_hello_type + client_hello_version + client_hello_tls_packet_length).decode('UTF-8'), "")).encode('UTF-8')
#---------------------------------------
# {server}  extract secret "early"
#---------------------------------------
	early_secret = hkdf.extract(variables.salt_value, variables.input_key_material, variables.hashtype)
#---------------------------------------------------
# {server}  create an ephemeral x25519 key pair
#---------------------------------------------------
	server_curve25519_clamp = curve25519.clamp(curve25519.decode_scalar25519(a2b_hex(functionkit.substitution(parameter.server_private_key_value))))
	server_curve25519_X25519 = curve25519.x25519(server_curve25519_clamp, 9)
	server_public_key = server_curve25519_X25519.to_bytes(32, 'little')
#--------------------------------------------------------
# {server}  construct a ServerHello handshake message
#--------------------------------------------------------
	server_hello_value = a2b_hex(functionkit.substitution(parameter.server_hello_message_value))
	tls13_handshake_server_hello = TLS13ServerHello(server_hello_value)
	key_exchange = tls13_handshake_server_hello.ext[0].server_share[0].key_exchange
#-----------------------------------------------------------
# {server}  derive secret for handshake "tls13 derived"
#-----------------------------------------------------------
	driver_secret = hkdf.derive_secret(early_secret, variables.derived_bytes, variables.emptiness_bytes, variables.hashtype)
#------------------------
# ECDH SECRET Create
#------------------------
	curve25519_X25519_value= curve25519.x25519(server_curve25519_clamp, client_curve25519_X25519)
	ecdh_secret = curve25519_X25519_value.to_bytes(32, 'little')
#------------------------------------------
# {server}  extract secret "handshake"
#------------------------------------------
	secret_handshake = hkdf.extract(driver_secret, ecdh_secret, variables.hashtype)
#-------------------------------------------------
# {server}  derive secret "tls13 c hs traffic"
#-------------------------------------------------
	client_handshake_traffic = hkdf.derive_secret(secret_handshake, variables.client_handshake_traffic_bytes, [a2b_hex(client_hello_value), server_hello_value], variables.hashtype)
#-------------------------------------------------
# {server}  derive secret "tls13 s hs traffic"
#-------------------------------------------------
	server_handshake_traffic = hkdf.derive_secret(secret_handshake, variables.server_handshake_traffic_bytes, [a2b_hex(client_hello_value), server_hello_value], variables.hashtype)
#-------------------------------------------------------
# {server}  derive secret for master "tls13 derived"
#-------------------------------------------------------
	master_secret_location = hkdf.derive_secret(secret_handshake, variables.derived_bytes, variables.emptiness_bytes, variables.hashtype)
#--------------------------------------
# {server}  extract secret "master"
#--------------------------------------
	master_secret = hkdf.extract(master_secret_location, variables.input_key_material, variables.hashtype)
#--------------------------------------
# {server}  send handshake record
#--------------------------------------
	server_hello_record = (variables.content_type_22 + variables.tls_version_12 + len(server_hello_value).to_bytes(2, 'big')) + server_hello_value
#------------------------------------------------------------
# {server}  derive write traffic keys for handshake data
#------------------------------------------------------------
	server_write_key_handshake = hkdf.expand_label(server_handshake_traffic, variables.key_bytes, variables.emptiness_bytes, variables.aes_key_length, variables.hashtype)
	server_write_initialization_vector_handshake = hkdf.expand_label(server_handshake_traffic, variables.initialization_vector_bytes, variables.emptiness_bytes, variables.initialization_vector_length, variables.hashtype)
#------------------------------------------------------------------
# {server}  construct an EncryptedExtensions handshake message
#------------------------------------------------------------------
	encrypted_extensions = a2b_hex(functionkit.substitution(parameter.encrypted_extensions_value))
	changecipherspec_header = (variables.content_handshake_type_20 + variables.tls_version_12 + len(encrypted_extensions).to_bytes(2, 'big'))
	encrypted_extensions_header = changecipherspec_header + encrypted_extensions
#---------------------------------------------------------
# {server}  construct a Certificate handshake message
#---------------------------------------------------------
	certificate = a2b_hex(functionkit.substitution(parameter.certificate_value))
	tls13_certificate = TLS13Certificate(certificate)
	tls13_certificate_cert = tls13_certificate[1][0].cert[1]
#--------------------------------------------------------------
# {server}  construct a CertificateVerify handshake message
#--------------------------------------------------------------
	certificateverify = a2b_hex(functionkit.substitution(parameter.certificateverify_value))
#----------------------------------------------------
# {server}  calculate finished "tls13 finished"
#----------------------------------------------------
	server_finished_key = hkdf.expand_label(server_handshake_traffic, variables.finished_bytes, variables.emptiness_bytes, variables.hash_length, variables.hashtype)
	server_verify_data = new(server_finished_key, hkdf.transcript_hash([a2b_hex(client_hello_value), server_hello_value, encrypted_extensions, certificate, certificateverify], variables.hashtype), sha256).digest()
#----------------------------------------------------
# {server}  construct a Finished handshake message
#----------------------------------------------------
	server_finished = variables.header_content_type_change_cipher_spec_20 + len(server_verify_data).to_bytes(3, 'big') + server_verify_data
#------------------------------------
# {server}  send handshake record
#------------------------------------
	changecipherspec_record = variables.content_handshake_type_20 + variables.tls_version_12 + variables.dummy_value
	tls_payload = encrypted_extensions + certificate + certificateverify + server_finished
	tls_record_header = variables.content_type_23 + variables.tls_version_12 + (len(tls_payload) + 1 + variables.message_authentication_code_tag_length).to_bytes(2, 'big')
	server_handshake_initialization_vector = functionkit.aes_initialization_vector(variables.sequence_numbers, client_curve25519_X25519, server_curve25519_X25519, server_write_initialization_vector_handshake)
#---------------
# Encryption
#---------------
	application_data_record = functionkit.encryption(server_write_key_handshake, server_handshake_initialization_vector, tls_payload, variables.content_type_22, tls_record_header)
#-------------------------------------------------
# {server} Client derive secret "tls13 c ap traffic"
#-------------------------------------------------
	messages = [a2b_hex(client_hello_value), server_hello_value, encrypted_extensions, certificate, certificateverify, server_finished]
	client_application_traffic = hkdf.derive_secret(master_secret, variables.client_application_traffic_bytes, messages, variables.hashtype)
	client_write_key_application = hkdf.expand_label(client_application_traffic, variables.key_bytes, variables.emptiness_bytes, variables.aes_key_length, variables.hashtype)
	client_write_initialization_vector_applicatoin = hkdf.expand_label(client_application_traffic, variables.initialization_vector_bytes, variables.emptiness_bytes, variables.initialization_vector_length, variables.hashtype)
#-------------------------------------------------
# {server}  derive secret "tls13 s ap traffic"
#-------------------------------------------------
	server_application_traffic = hkdf.derive_secret(master_secret, variables.server_application_traffic_bytes, messages, variables.hashtype)
#-------------------------------------------------
# {server}  derive secret "tls13 exp master"
#-------------------------------------------------
	exporter_master_secret = hkdf.derive_secret(master_secret, variables.export_master_bytes, messages, variables.hashtype)
#-------------------------------------------------------------
# {server}  derive write traffic keys for application data
#-------------------------------------------------------------
	server_write_key_application = hkdf.expand_label(server_application_traffic, variables.key_bytes, variables.emptiness_bytes, variables.aes_key_length, variables.hashtype)
	server_write_initialization_vector_application = hkdf.expand_label(server_application_traffic, variables.initialization_vector_bytes, variables.emptiness_bytes, variables.initialization_vector_length, variables.hashtype)
#-------------------------------------------------------------
# {server}  derive read traffic keys for handshake data
#-------------------------------------------------------------
	client_write_key_handshake = hkdf.expand_label(client_handshake_traffic, variables.key_bytes, variables.emptiness_bytes, variables.aes_key_length, variables.hashtype)
	client_write_initialization_vector_handshake = hkdf.expand_label(client_handshake_traffic, variables.initialization_vector_bytes, variables.emptiness_bytes, variables.initialization_vector_length, variables.hashtype)
#-------------------------------
# Send Server Packet
#-------------------------------
	send_server_packer = server_hello_record + changecipherspec_record + application_data_record
#-------------------------------
# Create Client Handshake(GCM)
#-------------------------------
	client_handshake_initialization_vector = functionkit.aes_initialization_vector(variables.sequence_numbers, client_curve25519_X25519, server_curve25519_X25519, client_write_initialization_vector_handshake)
#---------------------------------
# Create Server Application(GCM)
#---------------------------------
	server_application_initialization_vector = functionkit.aes_initialization_vector(variables.sequence_numbers, client_curve25519_X25519, server_curve25519_X25519, server_write_initialization_vector_application)
#---------------------------------------------------
# Client and Server Encryptoin Application Kit
#---------------------------------------------------
	encryption_applicationdata_kit = [client_write_key_application, client_write_initialization_vector_applicatoin, server_write_key_application, server_write_initialization_vector_application, client_curve25519_X25519, server_curve25519_X25519]
#-------------------------------
# Inheriting List
#-------------------------------
	inherting_list = [messages, master_secret, variables.hashtype, variables.hash_length, server_write_key_handshake, client_write_key_handshake, server_handshake_initialization_vector, client_handshake_initialization_vector, server_application_initialization_vector, server_write_key_application]
	
	return send_server_packer, inherting_list, encryption_applicationdata_kit