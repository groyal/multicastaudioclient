# multicastaudioclient
Python Multicast Audio Client

This is a python multicast client that supports TX/TX multicast RTP traffic.

* Sends Linear PCM 16bit 48000 audio from microphone device and sends PCMU out to multicast devices (eg Yealink T27G VOIP Phone)
* Recieves PCMU 8bit 8K traffic from multicast address and converts into PCM Linear 16bit 48K audio for playback to speaker device. 
* From Linear PCM it is possible to transcode to opus using librosa

This project is designed to form the basis for bridging to other systems that accept linear PCM or codecs like OPUS. 
