# AutOps
This Repository is dedicated for tools supporting Automation of IT Operations

# SerivceSniffer
ServiceSniffer is a python script used to sniff local services running on your server.
It is doing this by monitoring server TCP sessions and count the number of packets. 
A timestamp, TCP port and number of packets are stored in an XML file every 59s by default.
You can utilize these data to pull it and store it in a DB to be displayed in a graph to be monitored by NOC team.

# ServicesChecker
ServiceSniffer is a python script used to check a list of communication matrix tuples.
It is doing this by establishing SSH connection to all your servers. 
It will test the connection to all of external services listed on the communication matrix.
At the end of execution, you will receive a brief result.
