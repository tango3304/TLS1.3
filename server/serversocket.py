# Coding UTF-8

from socket import *
from handShake.send import serverhello, newsession, httpresponse, alert

#--------------------------
# Parameter Setting
#--------------------------
ipaddress = ''# WebServer IPaddress
port =  # Client Connection Port
max_connect = 1
bufsize = 4096

# =================================
# Main Processing
# =================================
if __name__ == '__main__':

#-----------------------------------------
# Socket Create
#-----------------------------------------
	server_socket = socket(AF_INET, SOCK_STREAM)
#-----------------------------------------
#Socket link IPaddress and Port
#-----------------------------------------
	server_socket.bind((ipaddress, port))
#-----------------------------------------
# Preparation for Socket to be Connect
#-----------------------------------------
	server_socket.listen(max_connect)

#================================
# 3Way Handshake
#================================
#-----------------------------------------
# Client Connect START
#-----------------------------------------
	print("Serving HTTP on 0.0.0.0 port " + str(port) + " (https://0.0.0.0:" + str(port) + "/) ...")
	connect, connection_ipaddress = server_socket.accept()


#================================
# TLS Handshake
#================================
#-----------------------------------------
# Receive from ClientHello
#-----------------------------------------
	receive_client_hello = connect.recv(bufsize)
#-----------------------------------------
# Send ServerHello Record to Client
#-----------------------------------------
	send_server_packer, inherting_list, encryption_applicationdata_kit = serverhello.server_hello_function(receive_client_hello)
	connect.send(send_server_packer)
#-----------------------------------------
# Receive from ClientFinished Record
#-----------------------------------------
	receive_client_finished = connect.recv(bufsize)
#-----------------------------------------
# Send NewSession Record to Client
#-----------------------------------------
	server_handshake_record = newsession.new_session_ticket(receive_client_finished, inherting_list)
	connect.send(server_handshake_record)


#================================
# Encrypt Communications
#================================	
#-----------------------------------------
# Receive from Client ApplicationData
#-----------------------------------------
	receive_client_application = connect.recv(bufsize)
#-----------------------------------------
# Send HTTP Response Data
#-----------------------------------------
	server_application_record, server_result = httpresponse.send_http_response_data(receive_client_application, encryption_applicationdata_kit, str(connection_ipaddress))
	connect.send(server_application_record)
	print(server_result)


#================================
# Fin
#================================
#-----------------------------------------
# Receive from Client Alert Record
#-----------------------------------------
	receive_client_alert = connect.recv(bufsize)
#-----------------------------------------
# Send Alert Record
#-----------------------------------------
	server_alert_record = alert.alert(receive_client_alert, encryption_applicationdata_kit)
	connect.send(server_alert_record)
#-----------------------------------------
# # Client Connection Finish
#-----------------------------------------
	connect.close()
	server_socket.close()