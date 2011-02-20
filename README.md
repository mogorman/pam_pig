PAM PIG
================================
Blah blah

Debian
======

1. Pre-requisites
-----------------
	apt-get install build-essential git-core libpam0g-dev libcurl4-gnutls-dev libqrencode-dev libpng12-dev

2. Installation
---------------

Installing pam module

	cp pam_pig.so /lib/security

Create secrets directory

	mkdir -p /etc/pig/secrets
	cp temp.key /etc/pig/secrets/<USER>

Configure Pam

**edit /etc/pam.d/common-auth adding this before pam_unix.so**

	# url: URL to pig_pen server
	# system_is_down: allow user to login even if pig_pen server is down
	# stacked_pass: pig password appended to normal pass, and passed to next pam
	auth required pam_pig.so sandwich=yes
	auth required pam_unix.so nullok_secure try_first_pass
	auth [success=1 default=ignore] pam_pig.so bottom=yes

OR

edit /etc/pam.d/common-auth  for password then oink

	auth    required        pam_unix.so try_first_pass nullok_secure                                                      
	auth    [success=1 default=ignore]     pam_pig.so 

Configure SSHD

edit /etc/ssh/sshd_config and change ChallengeResponseAuthentication AND UsePAM to:

	ChallengeResponseAuthentication yes
	UsePAM yes


	

TODO
----
* QR console output
* Make a deb
* Clean up init file
* Sign results
* Logging
* Verify permissions
* add support for base 10, and base 32 number systems
* convert to sha512 across board
* shift keysize 128
* rewrite avr code
* qr code base 64
* experation date
* output options
* hashing function phone apps
* figure out bug in qr code image generation
