#include <stdlib.h>
#include <stdio.h>
#include <qrencode.h>
#include <png.h>

#define KEY_SIZE 128


#define ANSI_RESET        "\x1B[0m"
#define ANSI_BLACKONGREY  "\x1B[30;47;27m"
#define ANSI_WHITE        "\x1B[27m"
#define ANSI_BLACK        "\x1B[7m"
#define UTF8_BOTH         "\xE2\x96\x88"
#define UTF8_TOPHALF      "\xE2\x96\x80"
#define UTF8_BOTTOMHALF   "\xE2\x96\x84"



/*taken from wpa supplicant bsd / gplv2 license */
static const unsigned char base64_table[65] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
unsigned char * base64_encode(const unsigned char *src, size_t len,
                              size_t *out_len)
{
        unsigned char *out, *pos;
        const unsigned char *end, *in;
        size_t olen;
        int line_len;

        olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
        olen += olen / 72; /* line feeds */
        olen++; /* nul termination */
        out = malloc(olen);
        if (out == NULL)
                return NULL;

        end = src + len;
        in = src;
        pos = out;
        line_len = 0;
        while (end - in >= 3) {
                *pos++ = base64_table[in[0] >> 2];
                *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
                *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
                *pos++ = base64_table[in[2] & 0x3f];
                in += 3;
                line_len += 4;
                if (line_len >= 72) {
                        *pos++ = '\n';
                        line_len = 0;
                }
        }

        if (end - in) {
                *pos++ = base64_table[in[0] >> 2];
                if (end - in == 1) {
                        *pos++ = base64_table[(in[0] & 0x03) << 4];
                        *pos++ = '=';
                } else {
                        *pos++ = base64_table[((in[0] & 0x03) << 4) |
                                              (in[1] >> 4)];
                        *pos++ = base64_table[(in[1] & 0x0f) << 2];
                }
                *pos++ = '=';
                line_len += 4;
        }

        if (line_len)
                *pos++ = '\n';

        *pos = '\0';
        if (out_len)
                *out_len = pos - out;
        return out;
}


/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
unsigned char * base64_decode(const unsigned char *src, size_t len,
                              size_t *out_len)
{
        unsigned char dtable[256], *out, *pos, in[4], block[4], tmp;
        size_t i, count, olen;

        memset(dtable, 0x80, 256);
        for (i = 0; i < sizeof(base64_table) - 1; i++)
                dtable[base64_table[i]] = (unsigned char) i;
        dtable['='] = 0;

        count = 0;
        for (i = 0; i < len; i++) {
                if (dtable[src[i]] != 0x80)
                        count++;
        }

        if (count == 0 || count % 4)
                return NULL;

        olen = count / 4 * 3;
        pos = out = malloc(olen);
        if (out == NULL)
                return NULL;

        count = 0;
        for (i = 0; i < len; i++) {
                tmp = dtable[src[i]];
                if (tmp == 0x80)
                        continue;

                in[count] = src[i];
                block[count] = tmp;
                count++;
                if (count == 4) {
                        *pos++ = (block[0] << 2) | (block[1] >> 4);
                        *pos++ = (block[1] << 4) | (block[2] >> 2);
                        *pos++ = (block[2] << 6) | block[3];
                        count = 0;
                }
        }

        if (pos > out) {
                if (in[2] == '=')
                        pos -= 2;
                else if (in[3] == '=')
                        pos--;
        }

        *out_len = pos - out;
        return out;
}


static int useBlockElements = 0;

/*taken from google-authenticator filed as gnu source imagine its lgpl v2.1 as it touches into qr land */
static void displayQRCode(unsigned const char *secret) {
        // Only newer systems have support for libqrencode. So, instead of requiring
        // it at build-time, we look for it at run-time. If it cannot be found, the
        // user can still type the code in manually, or he can copy the URL into
        // his browser.
        int i,x,y;
        if (isatty(1)) {
                QRcode *qrcode = QRcode_encodeString8bit((char *) secret, 0, 1);
                char *ptr = (char *)qrcode->data;
                // Output QRCode using ANSI colors. Instead of black on white, we
                // output black on grey, as that works independently of whether the
                // user runs his terminals in a black on white or white on black color
                // scheme.
                // But this requires that we print a border around the entire QR Code.
                // Otherwise, readers won't be able to recognize it.
                if (!useBlockElements) {
                        for (i = 0; i < 2; ++i) {
                                printf(ANSI_BLACKONGREY);
                                for (x = 0; x < qrcode->width + 4; ++x) printf("  ");
                                puts(ANSI_RESET);
                        }
                        for (y = 0; y < qrcode->width; ++y) {
                                printf(ANSI_BLACKONGREY"    ");
                                int isBlack = 0;
                                for (x = 0; x < qrcode->width; ++x) {
                                        if (*ptr++ & 1) {
                                                if (!isBlack) {
                                                        printf(ANSI_BLACK);
                                                }
                                                isBlack = 1;
                                        } else {
                                                if (isBlack) {
                                                        printf(ANSI_WHITE);
                                                }
                                                isBlack = 0;
                                        }
                                        printf("  ");
                                }
                                if (isBlack) {
                                        printf(ANSI_WHITE);
                                }
                                puts("    "ANSI_RESET);
                        }
                        for (i = 0; i < 2; ++i) {
                                printf(ANSI_BLACKONGREY);
                                for (x = 0; x < qrcode->width + 4; ++x) printf("  ");
                                puts(ANSI_RESET);
                        }
                } else {
                        // Drawing the QRCode with Unicode block elements is desirable as
                        // it makes the code much smaller, which is often easier to scan.
                        // Unfortunately, many terminal emulators do not display these
                        // Unicode characters properly.
                        printf(ANSI_BLACKONGREY);
                        for (i = 0; i < qrcode->width + 4; ++i) {
                                printf(" ");
                        }
                        puts(ANSI_RESET);
                        for (y = 0; y < qrcode->width; y += 2) {
                                printf(ANSI_BLACKONGREY"  ");
                                for (x = 0; x < qrcode->width; ++x) {
                                        int top = qrcode->data[y*qrcode->width + x] & 1;
                                        int bottom = 0;
                                        if (y+1 < qrcode->width) {
                                                bottom = qrcode->data[(y+1)*qrcode->width + x] & 1;
                                        }
                                        if (top) {
                                                if (bottom) {
                                                        printf(UTF8_BOTH);
                                                } else {
                                                        printf(UTF8_TOPHALF);
                                                }
                                        } else {
                                                if (bottom) {
                                                        printf(UTF8_BOTTOMHALF);
                                                } else {
                                                        printf(" ");
                                                }
                                        }
                                }
                                puts("  "ANSI_RESET);
                        }
                        printf(ANSI_BLACKONGREY);
                        for (i = 0; i < qrcode->width + 4; ++i) {
                                printf(" ");
                        }
                        puts(ANSI_RESET);
                }
                QRcode_free(qrcode);
        }
}



/*writePNG taken from qrencode which is gplv2.1 or later */
static int writePNG(QRcode *qrcode, const char *outfile)
{
	static FILE *fp; // avoid clobbering by setjmp.
	png_structp png_ptr;
	png_infop info_ptr;
	unsigned char *row, *p, *q;
	int x, y, xx, yy, bit;
        int margin = 4;
        int size = 5;
	int realwidth;

	realwidth = (qrcode->width + margin * 2) * size;
	row = (unsigned char *)malloc((realwidth + 7) / 8);
	if(row == NULL) {
		fprintf(stderr, "Failed to allocate memory.\n");
		exit(EXIT_FAILURE);
	}

	if(outfile[0] == '-' && outfile[1] == '\0') {
		fp = stdout;
	} else {
		fp = fopen(outfile, "wb");
		if(fp == NULL) {
			fprintf(stderr, "Failed to create file: %s\n", outfile);
			perror(NULL);
			exit(EXIT_FAILURE);
		}
	}

	png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if(png_ptr == NULL) {
		fprintf(stderr, "Failed to initialize PNG writer.\n");
		exit(EXIT_FAILURE);
	}

	info_ptr = png_create_info_struct(png_ptr);
	if(info_ptr == NULL) {
		fprintf(stderr, "Failed to initialize PNG write.\n");
		exit(EXIT_FAILURE);
	}

	if(setjmp(png_jmpbuf(png_ptr))) {
		png_destroy_write_struct(&png_ptr, &info_ptr);
		fprintf(stderr, "Failed to write PNG image.\n");
		exit(EXIT_FAILURE);
	}

	png_init_io(png_ptr, fp);
	png_set_IHDR(png_ptr, info_ptr,
                     realwidth, realwidth,
                     1,
                     PNG_COLOR_TYPE_GRAY,
                     PNG_INTERLACE_NONE,
                     PNG_COMPRESSION_TYPE_DEFAULT,
                     PNG_FILTER_TYPE_DEFAULT);
	png_write_info(png_ptr, info_ptr);

	/* top margin */
	memset(row, 0xff, (realwidth + 7) / 8);
	for(y=0; y<margin * size; y++) {
		png_write_row(png_ptr, row);
	}

	/* data */
	p = qrcode->data;
	for(y=0; y<qrcode->width; y++) {
		bit = 7;
		memset(row, 0xff, (realwidth + 7) / 8);
		q = row;
		q += margin * size / 8;
		bit = 7 - (margin * size % 8);
		for(x=0; x<qrcode->width; x++) {
			for(xx=0; xx<size; xx++) {
				*q ^= (*p & 1) << bit;
				bit--;
				if(bit < 0) {
					q++;
					bit = 7;
				}
			}
			p++;
		}
		for(yy=0; yy<size; yy++) {
			png_write_row(png_ptr, row);
		}
	}
	/* bottom margin */
	memset(row, 0xff, (realwidth + 7) / 8);
	for(y=0; y<margin * size; y++) {
		png_write_row(png_ptr, row);
	}

	png_write_end(png_ptr, info_ptr);
	png_destroy_write_struct(&png_ptr, &info_ptr);

	fclose(fp);
	free(row);

	return 0;
}

int main() {
        FILE * random_fd = fopen("/dev/urandom", "r");
        FILE * secret_file = fopen("temp.key", "w");
        u_int8_t byte;
        u_int8_t byte_array[KEY_SIZE] = {0};
        char hex_buffer[3];
        char print_buffer[(KEY_SIZE * 2)] = {0};
        unsigned char *secret;
        char finished_key[KEY_SIZE] = {0};
        int i, place = -1,  j = 0;
        QRcode *qrcode = NULL;
        printf("generating random key:");
        for( i = 0 ; i < KEY_SIZE; i++)
        {
                if( i % 25 == 0) {
	                printf(".");
                        fflush(stdout);
                }
                while(fread(&byte, 1, 1, random_fd) != 1) {
                        if(i != place) {
                                printf("+%d", i);
                                fflush(stdout);
                                place =  i;
                        }
                }
                finished_key[i] = byte;
                byte_array[i] = byte;
                snprintf(hex_buffer, 3 ,"%02X", byte);
                print_buffer[j++] = hex_buffer[0];
                print_buffer[j++] = hex_buffer[1];
        }
        fclose(random_fd);
        print_buffer[512] = '\0';
        printf("buffer:%s\nstrlen:%d\n", print_buffer,(int) strlen(print_buffer));
        secret = base64_encode(byte_array, KEY_SIZE, NULL);
        qrcode = QRcode_encodeString((char *) secret, 0, QR_ECLEVEL_L, QR_MODE_8, 0);
        displayQRCode(secret);
        fwrite(finished_key, KEY_SIZE, 1, secret_file);
        fclose(secret_file);
        if(qrcode == NULL) {
                perror("Failed to encode the input data:");
        } else {
                writePNG(qrcode, "temp.png");
                QRcode_free(qrcode);
        }
        printf("key was successfully generated\n");
        return 0;
}
