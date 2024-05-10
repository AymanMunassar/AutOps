"""
ServiceSniffer is a python script used to check a list of communication matrix tuples.
It is doing this by establishing SSH connection to all your servers. 
It will test the connection to all of external services listed on the communication matrix.
At the end of execution, you will receive a brief result.

Prerequists: 
install paramiko by running pip install paramiko
install pandas by running pip install pandas
install columnar by running pip install columnar

-- Working on only on Linux
"""

# Written by Ayman Munassar

"""
ServiceSniffer is a python script used to check a list of communication matrix tuples.
It is doing this by establishing SSH connection to all your servers. 
It will test the connection to all of external services listed on the communication matrix.
At the end of execution, you will receive a brief result.

Prerequists: 
install paramiko by running pip install paramiko
install pandas by running pip install pandas
install columnar by running pip install columnar

-- Working on only on Linux
"""

# Written by Ayman Munassar

import paramiko
import pandas as pd
import time
import sys
from columnar import columnar

collectDataReport = []
useList = []
username = 'username'
password = 'password'
ssh_connection_status = {}
i = 0
iT = 0


headers = ['Source IP','Destination IP', 'Port','Protocol','Status']

########################################################################################################Methods#############################################################################################

#This function establish ssh connection towards a server
def connectSSH(host, admin, passw):
   try:
      ssh = paramiko.SSHClient()
      ssh.load_host_keys('C:/Users/a.mohammed/.ssh/known_hosts')
      ssh.load_system_host_keys()
      ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      print(f'\033[1;37mTrying new connection to {host} . . .')
      ssh.connect(host, username=admin, password=passw, port=22, timeout=5)
   except paramiko.ssh_exception.AuthenticationException:
      print('\33[0;35mAuthentication failed\n\n')
      pass
   except paramiko.ssh_exception.SSHException:
      print('\33[0;35mUnable to establish SSH connection\n\n')
      pass
   except Exception as e:
      print(f'\33[0;35mAn error occurred: {e}\n\n')
      pass
   return ssh


def file_toList(file):
   sheet = pd.read_excel(file)
   df = pd.DataFrame(sheet, columns=['Source IP','Destination IP','Destination Port','Protocol'])
   hostList = list(df["Source IP"])
   destList = list(df["Destination IP"])
   portList = list(df["Destination Port"])
   protocolList = list(df["Protocol"])
   
   timer = 0
   loading = "Processing File:"
   print("Processing File Started . . .")
   while timer < 1.5:
      sys.stdout.write("=")
      time.sleep(0.01)
      timer += 0.01
   time.sleep(1)
   print("\nFile is processed successfually!")
   return hostList, destList, portList, protocolList


#This function test one touble
def test_tuple(ssh,ip,port,suit):
   source = ssh.get_transport().getpeername()[0]
   if suit=='TCP':
      stdin, stdout, stderr = ssh.exec_command(f'nc -zv -w 1 {ip} {port}')
   elif suit=='UDP':
      stdin, stdout, stderr = ssh.exec_command(f'nc -zvu -w 1 {ip} {port}')
   else:
      print('Please speicify the suit used TCP or UDP')

   if stdout.channel.recv_exit_status() == 0:
      print(f'\033[1;32m{ip}             {port}         {suit}       Connected!')
      collectDataReport.append([source,ip, port,suit, 'Connected!'])
   else:
      print(f'\033[1;31m{ip}             {port}         {suit}       Disconnected!')
      collectDataReport.append([source,ip, port,suit, 'Disconnected!'])



def sshing(host,user,passw):
   if(ssh_connection_status[host] == "Disconnected!"):
      ssh = connectSSH(host,user,passw)
      ssh_connection_status[host] == "Connected!"
      return ssh
   elif(ssh_connection_status[host] == "Connected!"):
      print(f"Connection is already established with {host}!")
      return ssh
   else:
      print("An erro found with the device connection status!")



hosts, IPs, PORTs, Protocol = file_toList(r"C:\Users\a.mohammed\Desktop\CheckPorts\Firewalling_Sheet.xlsx")

for ip in IPs:
   useList.append([hosts[i], IPs[i], PORTs[i], Protocol[i]])
   ssh_connection_status[hosts[i]] = 'Disconnected!'
   i = i+1


for host in hosts:
   
   ssh = sshing(host,username,password)
   if ssh.get_transport() is not None:
      stdin, stdout, stderr = ssh.exec_command('hostname')
      hostname = stdout.read().decode()

      if stdout.channel.recv_exit_status() == 0:
         print(f'\033[1;37mConnected to {hostname}')
      else:
         print(stderr)

      test_tuple(ssh,useList[iT][1],useList[iT][2],useList[iT][3])
   
   iT = iT+1
   ssh.close()


table = columnar(collectDataReport, headers,no_borders=True)
print(f'\033[1;37m-----------------------------------------------------------------------\nBrief report for all list')
print(table)
print(f'\033[1;37mSSH Session is terminated from all nodes')
print('-----------------------------------------------------------------------')
