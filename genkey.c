#include <stdlib.h>
#include <stdio.h>
#include <qrencode.h>
#include <png.h>

#define KEY_SIZE 256
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
        FILE * random_fd = fopen("/dev/random", "r");
        FILE * secret_file = fopen("temp.key", "w");
        u_int8_t byte;
        char hex_buffer[3];
        char print_buffer[(KEY_SIZE * 2)] = {0};
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
                snprintf(hex_buffer, 3 ,"%02X", byte);
                print_buffer[j++] = hex_buffer[0];
                print_buffer[j++] = hex_buffer[1];
        }
        fclose(random_fd);
        printf("\n");
        printf("buffer:%s\nstrlen:%d\n", print_buffer,(int) strlen(print_buffer));
        print_buffer[512] = '\0';
        printf("buffer:%s\nstrlen:%d\n", print_buffer,(int) strlen(print_buffer));
        qrcode = QRcode_encodeString(print_buffer, 0, QR_ECLEVEL_L, QR_MODE_8, 0);
        fwrite(finished_key, 256, 1, secret_file);
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
