import codecs
import sys
import subprocess
import numpy
import websocket
import socket
import struct
import json
import time
import logging
import pyaudio
from numpy import asarray, frombuffer, array, repeat, short, float32
import opuslib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
from threading import Thread,Lock
import traceback
import os
import librosa
import audioop
import pyrtp

logging.basicConfig(format='%(asctime)s %(levelname).1s %(funcName)s: %(message)s', level=logging.INFO)
LOG = logging.getLogger('Zellostream')

if os.name != 'nt':  #'nt' is Windows
	from pulseaudio import PulseAudioHandler

seq_num = 0

SECONDS = 0.02

# get the current working directory
current_working_directory = os.getcwd()

class ConfigException(Exception):
	pass

def get_config():
	config = {}

	with open(current_working_directory + "/config.json") as f:
		configdata = json.load(f)

	config["vox_silence_time"] = configdata.get("vox_silence_time", 3)
	config["audio_threshold"] = configdata.get("audio_threshold", 1000)
	config["input_device_index"] = configdata.get("input_device_index", 0)
	config["input_pulse_name"] = configdata.get("input_pulse_name")
	config["output_device_index"] = configdata.get("output_device_index", 0)
	config["output_pulse_name"] = configdata.get("output_pulse_name")
	config["audio_input_sample_rate"] = configdata.get("audio_input_sample_rate", 48000)
	config["audio_input_channels"] = configdata.get("audio_input_channels", 1)
	config["zello_sample_rate"] = configdata.get("zello_sample_rate", 16000)
	config["audio_output_sample_rate"] = configdata.get("audio_output_sample_rate", 48000)
	config["audio_output_channels"] = configdata.get("audio_output_channels", 1)
	config["audio_output_volume"] = configdata.get("audio_output_volume", 1)
	config["in_channel_config"] = configdata.get("in_channel", "mono")
	config["audio_source"] = configdata.get("audio_source","Sound Card")
	config["logging_level"] = configdata.get("logging_level", "warning")
	config["udp_port"] = configdata.get("UDP_PORT",9123)
	config["mcast_address"] = configdata.get("mcast_address", "239.10.10.10")
	config["mcast_port"] = configdata.get("mcast_port", 10000)
	return config


def get_default_input_audio_index(config, p):
	info = p.get_host_api_info_by_index(0)
	numdevices = info.get('deviceCount')
	output_device_names={}
	for i in range (0,numdevices):
		if p.get_device_info_by_host_api_device_index(0,i).get('maxOutputChannels')>0:
			device_info = p.get_device_info_by_host_api_device_index(0,i)
			output_device_names[device_info["name"]] = device_info["index"]
	return output_device_names.get("default", config["output_device_index"])


def get_default_output_audio_index(config, p):
	info = p.get_host_api_info_by_index(0)
	numdevices = info.get('deviceCount')
	input_device_names={}
	for i in range (0,numdevices):
		if p.get_device_info_by_host_api_device_index(0,i).get('maxInputChannels')>0:
			device_info = p.get_device_info_by_host_api_device_index(0,i)
			input_device_names[device_info["name"]] = device_info["index"]
	return input_device_names.get("default", config["input_device_index"])

def start_audio(config, p):
	audio_chunk = int(config["audio_input_sample_rate"] * SECONDS)  # 60ms = 960 samples @ 16000 S/s
	format = pyaudio.paInt16
	LOG.debug("open audio")

	if (config["input_pulse_name"] != None or config["output_pulse_name"] != None) and os.name != 'nt': # using pulseaudio
		pulse = PulseAudioHandler()

	# Audio input
	if config["input_pulse_name"] != None and os.name != 'nt': # using pulseaudio for input
		input_device_index = get_default_input_audio_index(config, p) # get default device first

	else: # use pyaudio device number
		input_device_index = config["input_device_index"]

	input_stream = p.open(
		format=format,
		channels=config["audio_input_channels"],
		rate=config["audio_input_sample_rate"],
		input=True,
		frames_per_buffer=audio_chunk,
		input_device_index=input_device_index,
	)
	LOG.debug("audio input opened")

	if config["input_pulse_name"] != None and os.name != 'nt': 
		LOG.error("input_pulse_name is %s",config["input_pulse_name"])
		pulse_source_index = pulse.get_source_index(config["input_pulse_name"])
		pulse_source_output_index = pulse.get_own_source_output_index()
		if pulse_source_index is None or pulse_source_output_index is None:
			LOG.warning(
				"cannot move source output %d to source %d",
				pulse_source_output_index,
				pulse_source_index
			)
		else:
			try:
				pulse.move_source_output(pulse_source_output_index, pulse_source_index)
				LOG.debug(
					"moved pulseaudio source output %d to source %d",
					pulse_source_output_index,
					pulse_source_index
				)
			except Exception as ex:
				LOG.error("exception assigning pulseaudio source: %s", ex)
	
	# Audio outpput
	if config["output_pulse_name"] != None and os.name != 'nt': # using pulseaudio for output
		output_device_index = get_default_output_audio_index(config, p)
	else: # use pyaudio device number
		output_device_index = config["output_device_index"]
	output_stream = p.open(
		format=format,
		channels=config["audio_output_channels"],
		rate=config["audio_output_sample_rate"],
		output=True,
		frames_per_buffer=audio_chunk,
		output_device_index=output_device_index,
	)
	LOG.debug("audio output opened")
	if config["output_pulse_name"] != None and os.name != 'nt': # redirect output from zellostream with pulseaudio
		LOG.error("output_pulse_name is %s",config["output_pulse_name"])
		pulse_sink_index = pulse.get_sink_index(config["output_pulse_name"])
		pulse_sink_input_index = pulse.get_own_sink_input_index()
		if pulse_sink_index is None or pulse_sink_input_index is None:
			LOG.warning(
				"cannot move pulseaudio sink input %d to sink %d",
				pulse_sink_input_index,
				pulse_sink_index
			)
		else:
			try:
				pulse.move_sink_input(pulse_sink_input_index, pulse_sink_index)
				LOG.debug(
					"moved pulseaudio sink input %d to sink %d",
					pulse_sink_input_index,
					pulse_sink_index
				)
			except Exception as ex:
				LOG.error("exception assigning pulseaudio sink: %s", ex)
	return input_stream, output_stream

#
#	Try and get data from the input stream at the configured sample_rate (usually 16K)
#	This will be linear PCM 16bit 
#	we need to convert this to PCMU 8bit 8K 
#	Return bytes in linear PCM
#
def record_chunk(config, stream, channel="mono"):

	audio_chunk = int(config["audio_input_sample_rate"] * SECONDS)
	alldata = bytearray()
	data = stream.read(audio_chunk)
	alldata.extend(data)
	data = frombuffer(alldata, dtype=short)

	z_data = data
	if channel == "left":
		z_data = z_data[0::2]
	elif channel == "right":
		z_data = z_data[1::2]
	elif channel == "mix":
		z_data = (z_data[0::2] + z_data[1::2]) / 2

	#return z_data
	return data

#
#	This runs on another thread and when traffic appears place onto updata variable 
#
def udp_mcast_rx(sock,config):
	global udpdata
	print("Start UDP multicast recieve")
	while processing:
		try:
			newdata = sock.recv(4096)
			#LOG.debug("got %d bytes ", len(newdata))
			with udp_buffer_lock:
				udpdata = udpdata + newdata
		except socket.timeout:
			pass

#
#	Recieves the inbound data from mcast address as udp_buffer_lock 
#	This buffer is converted if necessary to the correct sample rate. 
#
def get_udp_audio_mcast(config,seconds):
	global udpdata,udp_buffer_lock

	# the number of bytes to get are seconds * sample rate * 2 
	num_bytes = int(seconds*config["audio_input_sample_rate"]*2)  #.06 seconds * 8000 samples per second * 2 bytes per sample => 960 bytes per 60 ms

	with udp_buffer_lock: 
		#print(udpdata[:num_bytes])
		data = frombuffer(udpdata[:num_bytes], dtype=short)
		if len(data) == num_bytes/2:
			udpdata = udpdata[num_bytes:]
			#print("MCAST getting audio udpdata length is ",len(udpdata))
		else:
			data = numpy.empty(0, dtype=short)

	#this converts ulaw to 16bit linear PCM 
	data2 = audioop.ulaw2lin(data,2)
	# now convert from 8000 to 16000 
	data2 = audioop.ratecv(data2, 2, 1, 8000, 16000, None)[0]
		
	# data2 is returned at a sample rate of 16000 PCM linear, default zello sample rate 
	return data2

def bytes_to_uint32(bytes):
	return bytes[0]*(1<<24) + bytes[1]*(1<<16) + bytes[2]*(1<<8) + bytes[3]

#
#	The primary source is the Local audio. It 
#
#
def main():
	global udpdata,processing,udp_buffer_lock
	stream_id = None
	processing = True
	udpdata = b''

	try:
		config = get_config()
	except ConfigException as ex:
		LOG.critical("configuration error: %s", ex)
		sys.exit(1)

	log_level = logging.getLevelName(config["logging_level"].upper())
	LOG.setLevel(log_level)
		
	#
	#	CREATE THE AUDIO SOURCE AND SINK 
	# 	build the input/output stream for sound card
	#	
	#	Multicast - setup multicast reciever on thread 
	#
	print("Audio Source is " + config["audio_source"] )

	LOG.debug("start PyAudio")
	p = pyaudio.PyAudio()
	LOG.debug("started PyAudio")
	audio_input_stream, audio_output_stream = start_audio(config, p)

	#
	# multicast RX
	#
	LOG.debug("Set audio source to multicast " + config["mcast_address"] + " " + str(config["mcast_port"]))
	UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	UDPSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	listen_addr = (config["mcast_address"] ,config["mcast_port"])
	UDPSock.bind(listen_addr)
	#mreq = struct.pack("4sl", socket.inet_aton(config["mcast_address"]), socket.INADDR_ANY)
	mreq = struct.pack('=4s4s', socket.inet_aton(config["mcast_address"]), socket.inet_aton("192.168.151.122"))
	UDPSock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

	udp_rx_thread = Thread(target=udp_mcast_rx,args=(UDPSock,config))
	udp_rx_thread.start()
	udp_buffer_lock = Lock()

	#
	# CREATE SENDER MULTICAST 
	#
	UDPSender = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP, fileno=None)
	# This defines a multicast end point, that is a pair
    #   (multicast group ip address, send-to port nubmer)
	# 
	mgrp = (config["mcast_address"] ,config["mcast_port"])
	UDPSender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
	UDPSender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton("192.168.151.122"))
	# Transmit the datagram in the buffer
	#UDPSender.sendto(msgbuf, mgrp)

	#sequence_number = random.randint(1,9999)
	sequence_number = 54321
	#time_int = random.randint(1,9999)
	time_int = 12345
	packets = 3

	#
	#		Loop Through looking for audio from microphone 
	#		If it finds it, convert to g.711 and pass out into the multicast address
	#		Good to have a Yealink phone or other PCMU device to listen to port. 
	#
	while processing:
		try:
			#
			# firstly see if we have data from the microphone
			# data is returned as PCM 16bit 16K linear 
			data = record_chunk(config, audio_input_stream, channel=config["in_channel_config"])

			# now find the audio levels 
			has_data = False
			length_of_data = len(data)
			if length_of_data > 0:
				max_audio_level = max(abs(data))
				has_data = True
			else:
				max_audio_level = 0
				time.sleep(SECONDS)
			
			# if we have data and the max level is exceeded then 
			if has_data and max_audio_level > config["audio_threshold"]: 
				
				packet_id = 0  # packet ID is only used in server to client - populate with zeros for client to server direction
				quiet_samples = 0
				timer = time.time()

				while quiet_samples < (config["vox_silence_time"] * (1 / SECONDS)):

					data2 = data.tobytes()

					# this is linear PCM so we need convert to PCMU to send out 
					#this converts ulaw to 16bit linear PCM 
					data2 = audioop.lin2ulaw(data,2)
					print(len(data2))
					# now convert from 16000 to 8000 
					#data2 = audioop.ratecv(data2, 2, 1, 16000, 8000, None)[0]
					data3 = codecs.encode(data2, "hex").decode()

					packets = packets - 1
					time_int = time_int + 1
					sequence_number = sequence_number + 1

					# now create RTP Header 
					packet_vars = {'version' : 2, 'padding' : 0, 'extension' : 0, 'csi_count' : 0, 'marker' : 0, 'payload_type' : 0, 'sequence_number' : sequence_number, 'timestamp' : time_int, 'ssrc' : 185755418, 'payload' :  data3 }
					header_hex = pyrtp.GenerateRTPpacket(packet_vars)

					try:
						#######################################################################
						#nbytes = zello_ws.send_binary(send_data)
						if (max_audio_level > 0 ):
							UDPSender.sendto(bytes.fromhex(header_hex), mgrp)
						#######################################################################
					except Exception as ex:
						print(f" A01 error {ex}")
						break
					
					# keep getting data from audio input 
					data = record_chunk(config, audio_input_stream, channel=config["in_channel_config"])
					if len(data) > 0:
						max_audio_level = max(abs(data))
					else:
						max_audio_level = 0
						time.sleep(SECONDS)
					
					if len(data) == 0 or max_audio_level < config["audio_threshold"]:
						quiet_samples = quiet_samples + 1
					else:
						quiet_samples = 0

			#
			# `Monitor channel for incoming traffic from the multicast 
			else: 
				try:
					get_udp_audio_mcast(config,SECONDS)
				except Exception as ex:
					pass
		except KeyboardInterrupt:
			LOG.error("keyboard interrupt caught")
			processing = False

	LOG.info("terminating")
	audio_input_stream.close()
	audio_output_stream.close()
	p.terminate()
	time.sleep(1)
	UDPSock.close()
	UDPSender.close()

if __name__ == "__main__":
	main()
