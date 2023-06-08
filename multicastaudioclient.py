import codecs
import queue
import random
import sys
import socket
import struct
import json
import time
import logging
import pyaudio
from numpy import asarray, frombuffer, array, repeat, short, float32
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from threading import Thread,Lock
import os
import audioop
import pyrtp
import sox
from rtp import RTP, Extension, PayloadType
from copy import deepcopy
from scipy.io import wavfile

logging.basicConfig(format='%(asctime)s %(levelname).1s %(funcName)s: %(message)s', level=logging.INFO)
LOG = logging.getLogger('multicastclient')

if os.name != 'nt':  #'nt' is Windows
	from pulseaudio import PulseAudioHandler

seq_num = 0

# this is milliseconds 
SECONDS = 0.02

# get the current working directory
current_working_directory = os.getcwd()
AudioEncodingLINEAR16 = 1
AudioEncodingMULAW = 2

udp_buffer_lock = Lock()

class ConfigException(Exception):
	pass

def get_config():
	config = {}

	with open(current_working_directory + "/config.json") as f:
		configdata = json.load(f)

	config["vox_silence_time"] = configdata.get("vox_silence_time", 5)
	config["audio_threshold"] = configdata.get("audio_threshold", 1000)
	# these are the pulse devices for the audio 
	config["input_device_index"] = configdata.get("input_device_index", 0)
	config["input_pulse_name"] = configdata.get("input_pulse_name")
	config["output_device_index"] = configdata.get("output_device_index", 0)
	config["output_pulse_name"] = configdata.get("output_pulse_name")

	# sample rate for microphone and for speakers 
	config["audio_sample_rate_source"] = configdata.get("audio_sample_rate_source", 16000)
	config["audio_sample_rate_sink"] = configdata.get("audio_sample_rate_sink", 8000)
	config["audio_channels"] = configdata.get("audio_channels", 1)
	config["audio_bits"] = configdata.get("audio_bits", 16)
	config["audio_encoding"] = configdata.get("audio_encoding", "signed-integer")

	# sample rate for multicast - currently just u-law / a-law
	config["audio_mcast_encoding"] = configdata.get("audio_mcast_encoding", "u-law")
	config["audio_mcast_sample_rate"] = configdata.get("audio_mcast_sample_rate", 8000)
	config["mcast_address"] = configdata.get("mcast_address", "239.10.10.10")
	config["mcast_port"] = configdata.get("mcast_port", 10000)
	config["audio_mcast_interface_address"] = configdata.get("audio_mcast_interface_address", "any")

	config["in_channel_config"] = configdata.get("in_channel", "mono")

	config["logging_level"] = configdata.get("logging_level", "warning")

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

#
# 	Returns Audio stream from and to microphone/speaker 
#	16bit, 16000, Linear PCM 
#
def start_audio(config, p):
	audio_chunk = int(config["audio_sample_rate_source"] * SECONDS)  # 20ms = 960 samples @ 16000 S/s
	format = pyaudio.paInt16  #16bit signed integer
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
		channels=config["audio_channels"],
		rate=config["audio_sample_rate_source"],
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
		channels=1,
		rate=config["audio_sample_rate_sink"],
		output=True,
		frames_per_buffer=4096,
		output_device_index=output_device_index
	)
	"""
	if config["output_pulse_name"] != None and os.name != 'nt': 
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
	"""

	return input_stream, output_stream

#
#	Try and get data from the input stream at the configured sample_rate (usually 16K)
#	This will be linear PCM 16bit 
#	Return bytes in linear PCM with 160 bytes 20ms 
#
def record_chunk(config, stream, channel="mono"):

	audio_chunk = int(config["audio_sample_rate_source"] * SECONDS)

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

	return z_data

############################### MONITOR FOR INBOUND MCAST AND PLACE IN QUEUE ####################################
#	This runs on another thread and when traffic appears place onto updata variable 
#	Note we need to use the same ssrc for each session to make sure we dont pickup multicast originated from here
#
def udp_mcast_rx(sock,config, ssrc, audio_output_stream, seconds):
	global udpdata_rx, udp_buffer_lock
	ssrc_1 = hex(ssrc)[2:]

	num_bytes = 640

	while processing:
		try:
			newdata = sock.recv(1024)
			# find SSRC and check if it the same as mcast TX so can ignore
			in_ssrc = hex(newdata[8])[2:] + hex(newdata[9])[2:] + hex(newdata[10])[2:] + hex(newdata[11])[2:]
			# this is to make sure we dont pick up multicast traffic we sent 
			if (not ssrc == int(in_ssrc, 16)):
				# trim out the header 

				newdata = newdata[12:]
				with udp_buffer_lock:
					udpdata_rx = udpdata_rx + newdata
					data = frombuffer(udpdata_rx[:num_bytes], dtype=short)
					if len(data) == num_bytes/2:
						udpdata_rx = udpdata[num_bytes:]
						# for some reason sox conversion fails, but ulaw2lin works fine. 
						#datax = tfm_rx.build_array(input_array=data, sample_rate_in=8000)
						datax = audioop.ulaw2lin(data, 2)
						audio_output_stream.write(datax)

		except socket.timeout:
			pass

########################### SEND AUDIO OUT TO MCAST #############################################################
#
#	This thread waits for activity on the Queue. It is set SECONDS apart. 
# 	Once data turns up on the queue, it forwards it out the UDPSender socket to mgrp	
#
#
def send_mcast_from_queue(UDPSender, mgrp, SECONDS, config, ssrc):
	#check if data in queue 
	print("send mcast from queue started")
	sequence_number = 0
	time_int = random.randint(1,9999)
	# samplingrate / packets per second 0000 / 50 = 160
	incrementts = int(config["audio_mcast_sample_rate"] * SECONDS)
	#incrementts = 160

	while True:
		#if data in queue then send it 
		if (mcast_sender_queue.qsize() > 0):
			dpacket = mcast_sender_queue.get()
			
			time_int = time_int + incrementts
			sequence_number = sequence_number + 1

			packet_vars = {'version' : 2, 'padding' : 0, 'extension' : 0, 'csi_count' : 0, 'marker' : 1, 'payload_type' : 0, 'sequence_number' : sequence_number, 'timestamp' : time_int, 'ssrc' : ssrc, 'payload' :  dpacket }
			header_hex = pyrtp.GenerateRTPpacket(packet_vars)
			UDPSender.sendto(bytes.fromhex(header_hex), mgrp)
			time.sleep(SECONDS)


##################################################################################################################
#
#	The primary source is the Local audio Microphone -
#
#
def main():
	global udpdata, udpdata_rx, processing,udp_buffer_lock, mcast_sender_queue, tfm_rx

	stream_id = None
	processing = True
	udpdata = b''
	udpdata_rx = b''

	ssrc = random.randint(200000, 999999)

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

	LOG.debug("start PyAudio")
	p = pyaudio.PyAudio()
	LOG.debug("started PyAudio")
	audio_input_stream, audio_output_stream = start_audio(config, p)

	#fs, dm = wavfile.read('PinkPanther.wav')
	#audio_output_stream.write(dm)

	#
	# multicast RX
	#
	LOG.debug("Set audio source to multicast " + config["mcast_address"] + " " + str(config["mcast_port"]))
	UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	UDPSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	listen_addr = (config["mcast_address"] ,config["mcast_port"])
	UDPSock.bind(listen_addr)

	mreq = struct.pack('=4s4s', socket.inet_aton(config["mcast_address"]), socket.inet_aton(config["audio_mcast_interface_address"]))
	UDPSock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

	udp_rx_thread = Thread(target=udp_mcast_rx,args=(UDPSock,config, ssrc, audio_output_stream, SECONDS))
	udp_rx_thread.start()

	#
	# CREATE SENDER MULTICAST 
	#
	# This defines a multicast end point, that is a pair
    #   (multicast group ip address, send-to port nubmer)
	# 
	mgrp = (config["mcast_address"] ,config["mcast_port"])
	mcast_sender_queue = queue.Queue()

	# changed it here UDPSender -> UDPSock 
	udp_tx_thread = Thread(target=send_mcast_from_queue,args=(UDPSock, mgrp, SECONDS, config, ssrc))
	udp_tx_thread.start()
	udp_tx_buffer_lock = Lock()

#	sequence_number = random.randint(1,9999)
	sequence_number = 0
	time_int = random.randint(1,9999)
	#time_int = 12345
	packets = 3

	tfm_tx = sox.Transformer()
	tfm_tx.set_input_format(channels=config["audio_channels"], bits=config["audio_bits"], rate=config['audio_sample_rate_source'], file_type='s16')
	if ( config["audio_mcast_encoding"] == "u-law" ):
		tfm_tx.set_output_format(rate=8000, bits=8, channels=1, encoding="u-law" )
	elif ( config["audio_mcast_encoding"] == "a-law" ):
		tfm_tx.set_output_format(rate=8000, bits=8, channels=1, encoding="a-law" )

	print("Finished Initial processing ")
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
			data  = record_chunk(config, audio_input_stream, channel=config["in_channel_config"])
			has_data = False
			length_of_data = len(data)

			if length_of_data > 0:
				max_audio_level = max(abs(data))
				has_data = True
			else:
				max_audio_level = 0
				has_data = False
				
			# if we have data and the max level is exceeded then 
			if has_data and max_audio_level > config["audio_threshold"]: 
				
				packet_id = 0  # packet ID is only used in server to client - populate with zeros for client to server direction
				quiet_samples = 0
				timer = time.time()

				while quiet_samples < (config["vox_silence_time"] * (1 / SECONDS)):

					# this is signed 16bit linear PCM - needs to be 8bit unsigned PCMU

					datax = tfm_tx.build_array(input_array=data, sample_rate_in=config["audio_sample_rate_source"])
					#datax = audioop.lin2ulaw(data, 2)
					#datax = audioop.bias(datax, 1, 128)
					
					# sample_rate = 8000, bits = 8, channels = 1, encoding = u-law
					data4 = codecs.encode(datax, "hex").decode()
					mcast_sender_queue.put(data4)
					
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


		except KeyboardInterrupt:
			LOG.error("keyboard interrupt caught")
			processing = False

	LOG.info("terminating")

	audio_input_stream.close()
	audio_output_stream.close()
	p.terminate()
	time.sleep(1)
	UDPSock.close()

if __name__ == "__main__":

	main()
