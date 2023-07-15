# Coding UTF-8

from socket import *
from handShake.send import clienthello, clientfinished, httprequest, httprequestresult, connection_finish, parameter

#--------------------------
# Parameter Setting
#--------------------------
ipaddress = ''# WebServer IPaddress
port =  # WebServer Connection Port
bufsize = 4096

# =================================
# Main Processing
# =================================
if __name__ == '__main__':

#-----------------------------------------
# Socket Create
#-----------------------------------------
	client_socket = socket(AF_INET, SOCK_STREAM)

#================================
# 3Way Handshake
#================================
#------------------------------------------------
# Server Connection START
#------------------------------------------------
	client_socket.connect((ipaddress, port))


#================================
# TLS Handshake
#================================
#-----------------------------------------
# Send ClientHello Record to Server
#-----------------------------------------
	send_client_hello_record = clienthello.create_client_hello(parameter.client_private_key_value, parameter.client_message_value)
	client_socket.send(send_client_hello_record)
#-----------------------------------------
# Receive from ServerHello Record
#-----------------------------------------
	receive_server_hello = client_socket.recv(bufsize)
#-----------------------------------------
# Send ClientFinished Record to Server
#-----------------------------------------
	send_client_finished_packet, aes_write_application_list, curve25519_X25519_list = clientfinished.create_client_finished(receive_server_hello, send_client_hello_record)
	client_socket.send(send_client_finished_packet)
#-----------------------------------------
# Receive from NewSession Record
#-----------------------------------------
	receive_newsession = client_socket.recv(bufsize)


#================================
# Encrypt Communications
#================================
#---------------------------
# Send HTTP Request Data
#---------------------------
	send_http_request = httprequest.send_http_request_data(receive_newsession, aes_write_application_list)
	client_socket.send(send_http_request)
#-----------------------------------------
# Receive from HTTP Response Data
#-----------------------------------------
	receive_http_response = client_socket.recv(bufsize)


#================================
# Fin
#================================
#-------------------------------------------
# HTTP Response Data & Send Alert Record
#-------------------------------------------
	handshake_record = httprequestresult.http_response_data(receive_http_response, aes_write_application_list, curve25519_X25519_list)
	client_socket.send(handshake_record)
#-----------------------------------------
# Receive from Alert Record
#-----------------------------------------
	receive_alert_response = client_socket.recv(bufsize)
#-----------------------------------------
# Server Connection Finish
#-----------------------------------------
	record_value = connection_finish.http_response_data(receive_alert_response, aes_write_application_list, curve25519_X25519_list)
	client_socket.close()