#include <stdio.h>    /* Standard input/output definitions */
#include <stdlib.h>
#include <stdint.h>   /* Standard types */
#include <string.h>   /* String function definitions */
#include <unistd.h>   /* UNIX standard function definitions */
#include <fcntl.h>    /* File control definitions */
#include <errno.h>    /* Error number definitions */
#include <termios.h>  /* POSIX terminal control definitions */
#include <sys/ioctl.h>
#include <getopt.h>
#include <time.h>

// -p port
// -f file
//
void usage(void) {
        printf("Usage: transmitkey -p <serialport> -f <file> [OPTIONS]\n"
               "\n"
               "Options:\n"
               "  -h --help                      Print this help message\n"
               "  -p --port                      port to select /dev/ttyUSB0\n"
               "  -f --file                      Hash to push to key\n"
               "\n"
                );
}

int serialport_init(const char* serialport)
{
    struct termios toptions;
    int fd;

    //fprintf(stderr,"init_serialport: opening port %s @ %d bps\n",
    //        serialport,baud);

    fd = open(serialport, O_RDWR | O_NOCTTY | O_NDELAY);
    if (fd == -1)  {
        perror("init_serialport: Unable to open port ");
        return -1;
    }

    if (tcgetattr(fd, &toptions) < 0) {
        perror("init_serialport: Couldn't get term attributes");
        return -1;
    }
    speed_t brate = B9600;

    cfsetispeed(&toptions, brate);
    cfsetospeed(&toptions, brate);

    // 8N1
    toptions.c_cflag &= ~PARENB;
    toptions.c_cflag &= ~CSTOPB;
    toptions.c_cflag &= ~CSIZE;
    toptions.c_cflag |= CS8;
    // no flow control
    toptions.c_cflag &= ~CRTSCTS;

    toptions.c_cflag |= CREAD | CLOCAL;  // turn on READ & ignore ctrl lines
    toptions.c_iflag &= ~(IXON | IXOFF | IXANY); // turn off s/w flow ctrl

    toptions.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG); // make raw
    toptions.c_oflag &= ~OPOST; // make raw

    // see: http://unixwiz.net/techtips/termios-vmin-vtime.html
    toptions.c_cc[VMIN]  = 0;
    toptions.c_cc[VTIME] = 20;

    if( tcsetattr(fd, TCSANOW, &toptions) < 0) {
        perror("init_serialport: Couldn't set term attributes");
        return -1;
    }

    return fd;
}


int serialport_write(int fd, const unsigned char* str, int len)
{
        int n;
        int i;
        uint8_t byte;
        for( i = 0; i < len; i++) {
                usleep( 10 * 1000 ); // wait 10 msec try again
                byte = str[i];
                n = write(fd, &byte, 1);
                if( n!=1 )
                        return -1;
        }
        return 0;
}

int serialport_read(int fd, char res) {
        char b[1] = {0};
        int time = 1000;
        do {
                int n = read(fd, b, 1);  // read a char at a time
                if( n==-1) {
                        usleep( 10 * 1000 ); // wait 10 msec try again
                }
                if( n==0 ) {
                        usleep( 10 * 1000 ); // wait 10 msec try again
                }
                if( b[0] == res ) {
                        return 0;
                }
                time--;
        } while(time);

        return 1;
}

int main(int argc, char *argv[])
{
        u_int8_t inbyte, j, mix = 0;
        u_int16_t temp_crc = 0;
        u_int8_t *pointer;
        time_t timestamp;
        int fd = 0;
        char serialport[256] = {"/dev/ttyUSB0"};
        char file[256] = {0};
        unsigned char buffer[262] = {0};
        int i;
        FILE *f;

        if (argc==1) {
                usage();
                exit(EXIT_SUCCESS);
        }

        int option_index = 0, opt;
        /* parse options */
        static struct option loptions[] = {
                {"help", no_argument,       0, 'h'},
                {"port", required_argument, 0, 'p'},
                {"file", required_argument, 0, 'b'}
        };

        while(1) {
                opt = getopt_long(argc, argv, "hp:f:",
                                  loptions, &option_index);
                if(opt==-1) break;
                switch (opt) {
                case '0':
                        break;
                case 'h':
                        usage();
                        exit(EXIT_SUCCESS);
                        break;
                case 'p':
                        strncpy(serialport, optarg, sizeof(serialport));
                        fd = serialport_init(optarg);
                        if(fd==-1) return -1;
                        break;
                case 'f':
                        strncpy(file, optarg, sizeof(file));
                        break;
                }
        }

        if(file[0] == '\0') {
                fprintf(stderr, "no file to send\n");
                return 1;
        }
        if(serialport_read(fd, '2')) {
                fprintf(stderr, "could not sync with device\n");
                return 2;
        }
        tcflush(fd, TCIOFLUSH);
        timestamp = time(0);
        buffer[0] = (u_int8_t) timestamp;
        buffer[1] = (u_int8_t) (timestamp >> 8);
        buffer[2] = (u_int8_t) (timestamp >> 16);
        buffer[3] = (u_int8_t) (timestamp >> 24);
        pointer = buffer+4;
        f = fopen(file, "r");
        fread(pointer, 256,1, f);
        for ( i = 0; i < 260; i++) {
                inbyte = buffer[i];
                for (j=0;j<8;j++) {
                        mix = ((u_int8_t) (temp_crc)^ inbyte) & 0x01;
                        temp_crc = temp_crc >> 1;
                        if (mix) {
                                temp_crc = temp_crc ^ 0xA001;
                        }
                        inbyte = inbyte >> 1;
                }
        }
//        printf("temp_crc = %d\n", temp_crc);
        pointer = (u_int8_t *) &temp_crc;
        buffer[260] = *pointer++;
        buffer[261] = *pointer;
        if(serialport_write(fd, buffer, 262)) {
                fprintf(stderr, "failed to write\n");
                return 3;
        }
        if(serialport_read(fd,'v')) {
                fprintf(stderr, "CRC did not match\n");
                return 4;
        }
	/* u_int32_t test = 69; */
        /* u_int8_t *pointer; */
        /* pointer = &test; */
        /* *pointer = 0; */
        /* /\* pointer++; *\/ */
        /* /\* *pointer = 0; *\/ */
        /* /\* pointer++; *\/ */
        /* /\* *pointer = 0; *\/ */
        /* /\* pointer++; *\/ */
        /* pointer +=0; */
        /* *pointer = 255; */

	/* printf("oh hi %d %d\n", test, *pointer); */
        printf("success\n");
	return 0;
}


