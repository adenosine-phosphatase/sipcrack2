# sipcrack2
mitm_relay.py output parser and sipdump+sipcrack integrated password cracker

sipcrack2 was developed to facilitate password cracking from a mitm_relay.py output. The reason for this is that mitm_relay.py generates decryted SIP session from an intercepted SIP dialog. sipdump.py script from KALI is not able to parse pcap file that is encrypted.
Even if we have a private key to decrypt the pcap, sipdump.py does not support the import of that private key.

Therefore, sipcrack2 will read the decrypted output of mitm_relay, find the digest attributes and run password brute forcing against found responses.

Compile it with:
gcc sipcrack2.c -lcrypto -o sipcrack2
