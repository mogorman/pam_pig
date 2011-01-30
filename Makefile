
all: pam_pig

pam_pig:
	gcc -Werror -Wall   genkey.c  -lqrencode -lpng12 -o pig-genkey
	gcc -Werror -Wall   transmitkey.c  -lqrencode -lpng12 -o pig-transmitkey
	gcc -Werror -Wall   verifykey.c -o pig-verifykey -lnettle
	gcc -fPIC -lcurl -c pam_pig.c
	gcc -lpam test-pam.c -o test-pam
	ld -l curl -x --shared -o pam_pig.so pam_pig.o
	gcc -Werror -Wall -pthread -g pig_pen.c mongoose.c hmac_sha2.c sha2.c -ldl -pthread  -o pig_pen
#	gcc sha2.o hmac.o -o pig_pen

clean:
	rm -f *.so *.o pig-genkey pig_pen pig-transmitkey pig-verifykey test-pam

macosx:
	gcc -fPIC -D MACOSX=1 -c pam_pig.c
	gcc -lpam -D MACOSX=1 test-pam.c -o test-pam
	ld -lpam  -lcurl  -lcrypto -lm  -lz -lc -dylib -x -o pam_pig.so pam_pig.o
	gcc -Werror -Wall -pthread -g pig_pen.c mongoose.c -l nettle -ldl -pthread   -o pig_pen

