# UTF-8 Coding

from binascii import a2b_hex, hexlify
from scapy.layers.tls.record_tls13 import TLS
from ..subfunction import functionkit
from . import variables
from os.path import isfile
import datetime

# =================================
# Main Function
# =================================
def send_http_response_data(client_application_data, encryption_applicationdata_kit, connection_ipaddress):

#-------------------------------------------------
# encryption_applicationdata_kit Extraction
#-------------------------------------------------
	client_write_key_application = encryption_applicationdata_kit[0]
	client_write_initialization_vector_applicatoin = encryption_applicationdata_kit[1]
	server_write_key_application = encryption_applicationdata_kit[2]
	server_write_initialization_vector_application = encryption_applicationdata_kit[3]
	client_curve25519_X25519 = encryption_applicationdata_kit[4]
	server_curve25519_X25519 = encryption_applicationdata_kit[5]
#--------------------------------------------------
# Client CipheText and Client Tag 
#--------------------------------------------------
	record_header_type = TLS(client_application_data).type.to_bytes(1, 'big')
	record_header_version = TLS(client_application_data).version.to_bytes(2, 'big')
	record_header_len = TLS(client_application_data).len.to_bytes(2, 'big')
	record_header = record_header_type + record_header_version + record_header_len
	client_aead_encrypted = a2b_hex((hexlify(client_application_data).decode('UTF-8').replace(hexlify(record_header).decode('UTF-8'), "")).encode('UTF-8'))
	client_ciphertext = client_aead_encrypted[0:(len(client_aead_encrypted) - variables.message_authentication_code_tag_length)]
	client_tag = client_aead_encrypted[(len(client_aead_encrypted) - variables.message_authentication_code_tag_length):len(client_aead_encrypted)]
#-----------------------------------
# decryption Client Recive Data
#-----------------------------------
	decryption_data = functionkit.decryption(client_write_key_application, client_write_initialization_vector_applicatoin, client_ciphertext, client_tag)
	client_data = decryption_data[0:(len(decryption_data) - 1)]
#----------------------------------------
# HTTP Request Acquisition Response
#----------------------------------------
	client_data_list = str(client_data, 'iso-8859-1').split()
	request_method, request_uri ,request_version, _, host_ipaddress, _, connection = client_data_list[:len(client_data_list)]
	absolute_path = '/var/www/html' + request_uri
	
	if isfile(absolute_path):
		status_code = request_version + ' 200 OK\r\n'
		date = "Date: "
		date += (datetime.date.today()).strftime('%a') + ", "
		date += (datetime.date.today()).strftime('%d') + " "
		date += (datetime.date.today()).strftime('%b') + " "
		date += (datetime.date.today()).strftime('%Y') + " "
		date += datetime.datetime.now().strftime("%H:%M:%S") + " GMT\r\n"
		
		with open(absolute_path) as f:
			send_request = status_code.encode('UTF-8')
			send_request += date.encode('UTF-8')
			send_request += ("Connection: " + connection + "\r\n").encode('UTF-8')
			send_request += (f.read() + "\r\n").encode('UTF-8')
			
		server_result = connection_ipaddress + "  - - "
		server_result += "[" + (datetime.date.today()).strftime('%d') + "/"
		server_result += (datetime.date.today()).strftime('%b') + "/"
		server_result += (datetime.date.today()).strftime('%Y') + " "
		server_result += datetime.datetime.now().strftime("%H:%M:%S") + "]"
		server_result += ' "' + request_method + " " + request_uri + ' ' + request_version + '" 200 -' 
	else:
		status_code = request_version + ' 404 Not Found\r\n'
		date = "Date: "
		date += (datetime.date.today()).strftime('%a') + ", "
		date += (datetime.date.today()).strftime('%d') + " "
		date += (datetime.date.today()).strftime('%b') + " "
		date += (datetime.date.today()).strftime('%Y') + " "
		date += datetime.datetime.now().strftime("%H:%M:%S") + " GMT\r\n"
		
		send_request = status_code.encode('UTF-8')
		send_request += date.encode('UTF-8')
		send_request += ("Connection: " + connection + "\r\n").encode('UTF-8')
		
		server_result = connection_ipaddress + "  - - "
		server_result += "[" + (datetime.date.today()).strftime('%d') + "/"
		server_result += (datetime.date.today()).strftime('%b') + "/"
		server_result += (datetime.date.today()).strftime('%Y') + " "
		server_result += datetime.datetime.now().strftime("%H:%M:%S") + "]"
		server_result += " code 404, message File not found\r\n"
		server_result += connection_ipaddress + "  - - "
		server_result += "[" + (datetime.date.today()).strftime('%d') + "/"
		server_result += (datetime.date.today()).strftime('%b') + "/"
		server_result += (datetime.date.today()).strftime('%Y') + " "
		server_result += datetime.datetime.now().strftime("%H:%M:%S") + "]"
		server_result += ' "' + request_method + " " + request_uri + ' ' + request_version + '" 404 -'
#----------------------------------------
# Encryption 
#----------------------------------------
	tls_record_header = variables.content_type_23 + variables.tls_version_12 + (len(send_request) + 1 + variables.message_authentication_code_tag_length).to_bytes(2, 'big')
	server_application_initialization_vector = functionkit.aes_initialization_vector((variables.sequence_numbers + 1), client_curve25519_X25519, server_curve25519_X25519, server_write_initialization_vector_application)
	server_application_record = functionkit.encryption(server_write_key_application, server_application_initialization_vector, send_request, variables.content_type_23, tls_record_header)
	
	return server_application_record, server_result