PAM PIG
================================
Blah blah

Debian
------

1. Pre-requisites

	apt-get install build-essential git-core libcurl4-gnutls-dev libqrencode-dev libpng12-dev

2. Installation

	cp pam_pig.so /lib/security
	cp pig_pen.init /etc/init.d
	cp pig_pen /usr/local/bin
	update-rc.d pig_pen.init defaults

	mkdir -p /etc/pig/secrets
	cp temp.key /etc/pig/secrets/jimshoe

	mkdir -p /etc/pig/ids
	echo <USER> > /etc/pig/ids/<USER>

	edit /etc/pam.d/common-auth adding this before pam_unix.so

	# url: URL to pig_pen server
	# system_is_down: allow user to login even if pig_pen server is down
	# stacked_pass: pig password appended to normal pass, and passed to next pam
	auth       required                        pam_pig.so url=http://localhost:4240/auth/ system_is_down=allow stacked_pass=yes 
	auth       [success=1 default=ignore]      pam_unix.so try_first_pass nullok_secure

	OR

	edit /etc/pam.d/common-auth  for password then oink

	auth    required        pam_unix.so try_first_pass nullok_secure                                                      
	auth    [success=1 default=ignore]     pam_pig.so url=http://localhost:4240/auth/ system_is_down=allow stacked_pass=no

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
