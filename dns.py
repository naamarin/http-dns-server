#By Naama Iluz ID 212259204
import socket
import select
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR

IP_ = '0.0.0.0'
PORT_ = 8153
SOCKET_TIMEOUT = 10
REPLAY_ON_WRONG_REQUEST = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n"


def wrong_request(client_socket, deatails):
    """ Handles the case where the requested ip or domain name is invalid """
    http_response = REPLAY_ON_WRONG_REQUEST.format(len(deatails)) + deatails
    client_socket.send(http_response.encode())

def check_ip(ip_addr):
    """Checks if the requested IP is invalid - if it contains letters, impossible values or is too short"""
    valid_ip = list(filter(lambda x: x.isdigit(),ip_addr)) #Checks if all items are numbers
    if valid_ip != ip_addr: #if not returns true
        return True
    ip_addr_sum = reduce(lambda x,y: int(x) + int(y),ip_addr) #convert all items to int (from str)
    if len(ip_addr) != 4 or ip_addr_sum > 1020:
        return  True
    return False

def handle_client_request(resource, client_socket):
    """ Check the required resource, generate proper HTTP response and send to client"""
    url = resource[1:]
    if "reverse" in resource:
        url = url.split("/")
        url = url[1].split(".")
        if check_ip(url): #returns True if ip is invalid
            wrong_request(client_socket, "Wrong IP address")
            return
        reverse_ip_address = url[3] + "." + url[2] + "." + url[1] + "." + url[0]
        #verbose=0
        packet = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname= reverse_ip_address+".in-addr.arpa",qtype="PTR"))
        response = sr1(packet,verbose=0)
        if response[DNS].rcode == 3:
            http_response = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 18\r\n\r\nIP does not exists"
        else:
            http_response = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n".format(len(response[DNS].an.rdata)) + response[DNS].an.rdata.decode()
        client_socket.send(http_response.encode())
        return
    # Create the DNS packet and send it
    packet = IP(dst="8.8.8.8")/UDP()/DNS(rd=5,qd=DNSQR(qname=url))
    response = sr1(packet,verbose=0)
    if response[DNS].rcode != 0: #rcode=0 -> ok
        wrong_request(client_socket, "Wrong domain name")
        return
    # Get the IP addresses from the DNS response

    ip_addresses = [response[DNS][DNSRR][i].rdata for i in range(0,response[DNS].ancount) if response[DNS][DNSRR][i].type == 1]

    htmlFile = "<ul>\n"
    for item in ip_addresses:
        htmlFile += "<li>{}</li>\n".format(item)
    htmlFile += "</ul>"
    http_response = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n".format(len(htmlFile)) + htmlFile
    client_socket.send(http_response.encode())
    return


def validate_http_request(request):
    """
    Check if request is a valid HTTP request and returns TRUE / FALSE and the requested URL
    """
    words = request.split("\r\n")
    words = words[0].split(" ")
    if len(words) == 3 and words[0] == "GET" and words[2] == "HTTP/1.1":
        return True, words[1]
    return False, ""

def handle_client(client_socket):
    """ Handles client requests: verifies client's requests are legal HTTP, calls function to handle the requests """
    print('Client connected')
    #client_socket.send(FIXED_RESPONSE.encode())

    while True:
        # TO DO: insert code that receives client request
        client_request = client_socket.recv(1024).decode()
        valid_http, resource = validate_http_request(client_request)
        if valid_http:
            print('Got a valid HTTP request')
            handle_client_request(resource, client_socket)
            break
        else:
            print('Error: Not a valid HTTP request')
            break

    print('Closing connection')
    client_socket.close()


def main():
    # Open a socket and loop forever while waiting for clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP_, PORT_))
    server_socket.listen()
    print("Listening for connections on port {}".format(PORT_))

    while True:
        try:
            timeout = 5  # in seconds
            ready = select.select([server_socket], [], [], timeout)
            if ready[0]:
                client_socket, client_address = server_socket.accept()
            else:
                print("No web conection");
                return
            #client_socket, client_address = server_socket.accept()
            print('New connection received')
            client_socket.settimeout(SOCKET_TIMEOUT)
            handle_client(client_socket)
        except:
            print("Time's up!")
            return


if __name__ == "__main__":
    # Call the main handler function
    main()
