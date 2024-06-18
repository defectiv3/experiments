#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

/*
 + TIMsplit
 +
 + Given a binary file that has many TIM structures squashed in it, this program
 + parses them and writes each one into its own file.
 +
 + This program was written to parse a file DUMMY.CDA found inside the Guilty Gear
 + (1998-JP) psx game. It has only been tested on 4bpp TIM files but it should work
 + on the rest too hopefully. ::)
 +
 + Very much barebone, I'd love to improve it if I find more uses for it while REing
 + shit.
 +
 + some ideas
 + - add a parser that works headerless, i.e. assume data[0] contains a TIM structure
 +   without a header, and parse from there. To be able to do this, the program needs
 +   to assume the bpp, so it should be a parameter passed by the user.
 + - add a parameter to dry-run the program without generating any files, only
 +   printing the structures.
 */

#define READALL_CHUNK (2 * 1024 * 1024)
#define BYTES_PER_COLOR 2

struct tim_hdr {
	uint32_t magic;
	uint32_t version;
};

struct tim_clut_hdr {
	uint32_t offset;
	uint16_t org_x;
	uint16_t org_y;
	uint16_t n_colors_clut;
	uint16_t n_cluts;
};

struct tim_img_hdr {
	uint32_t offset;
	uint16_t org_x;
	uint16_t org_y;
	uint16_t width;
	uint16_t height;
};

enum readall_ret {
	READALL_OK       = 0,
	READALL_NO_MEM   = 1,
	READALL_OVERFLOW = 2,
	READALL_ERROR    = 3,
	READALL_INVALID  = 4,
};

enum readall_ret readall(FILE *fp, char **dataptr, size_t *sizeptr) {
	char *data = NULL, *temp;
	size_t size = 0, used = 0, n;

	if (fp == NULL || dataptr == NULL || sizeptr == NULL) {
		return READALL_INVALID;
	}

	if (ferror(fp)) {
		return READALL_ERROR;
	}

	while(1) {
		if (used + READALL_CHUNK + 1 > size) {
			size = used + READALL_CHUNK + 1;

			/* checking if size has overflown */
			if (size < used) {
				free(data);
				return READALL_OVERFLOW;
			}

			temp = realloc(data, size);
			if (temp == NULL) {
				free(data);
				return READALL_NO_MEM;
			}

			data = temp;
		}

		n = fread(data + used, sizeof(char), READALL_CHUNK, fp);
		if (n == 0) {
			break;
		}

		used += n;
	}

	if (ferror(fp)) {
		free(data);
		return READALL_ERROR;
	}

	temp = realloc(data, used + 1);
	if (temp == NULL) {
		free(data);
		return READALL_NO_MEM;
	}
	data = temp;
	data[used] = '\0';

	*dataptr = data;
	*sizeptr = used;

	return READALL_OK;
}

int main(int argc, char **argv) {
	int ret;
	bool err = false;

	if (argc != 2) {
		printf("usage: %s <filename>\n", argv[0]);
		return EXIT_FAILURE;
	}

	FILE *in = fopen(argv[1], "r");
	if (in == NULL) {
		perror("could not open file");
		return EXIT_FAILURE;
	}

	char  *data = NULL;
	size_t datasz;

	ret = readall(in, &data, &datasz);
	if (ret != 0) {
		err = true;
		goto end;
	}

	size_t off = 0;
	while (off < datasz) {
		if (off + sizeof(struct tim_hdr) > datasz) {
			break;
		}

		char *start = data + off;
		struct tim_hdr *hdr = (struct tim_hdr *)(data + off);
		bool is_tim = hdr->magic == 0x10 &&
			(hdr->version == 0x2 || hdr->version == 0x3 ||
			 hdr->version == 0x8 || hdr->version == 0x9);
		
		off += sizeof(struct tim_hdr);

		if (!is_tim) {
			continue;
		}
		
		// parse the clut header only present on version 8 and 9
		// technically this should be checked by whether the bit 4 of version
		// is set or not, but the result is the same afaik :P
		if (hdr->version == 0x8 || hdr->version == 0x9) {
			if (off + sizeof(struct tim_clut_hdr) > datasz) {
				printf("detected a TIM header but could not parse it due to EOF\n");
				break;
			}

			struct tim_clut_hdr *clut_hdr = (struct tim_clut_hdr *)(data + off);
			size_t clut_data_sz = clut_hdr->n_colors_clut * BYTES_PER_COLOR * clut_hdr->n_cluts;

			if (off + sizeof(struct tim_clut_hdr) + clut_data_sz > datasz) {
				printf("detected a TIM header but could not parse it due to EOF\n");
				break;
			}
			
			// printf("offset %d ;; pal_org_x %u ;; pal_org_y %u ;; n_colors_clut "
			// 			 "%u ;; n_cluts %u ;; data_sz %ld\n",
			// 			 clut_hdr->offset, clut_hdr->org_x, clut_hdr->org_y,
			// 			 clut_hdr->n_colors_clut, clut_hdr->n_cluts, clut_data_sz);
			
			off += sizeof(struct tim_clut_hdr) + clut_data_sz;
		}

		if (off + sizeof(struct tim_img_hdr) > datasz) {
			printf("detected a TIM header but could not parse it due to EOF\n");
			break;
		}

		struct tim_img_hdr *img_hdr = (struct tim_img_hdr *)(data + off);
		size_t img_data_sz = img_hdr->height * (img_hdr->width * 2);

		if (off + sizeof(struct tim_clut_hdr) + img_data_sz > datasz) {
			printf("detected a TIM header but could not parse it due to EOF\n");
			break;
		}
		
		// printf("offset %d ;; img_org_x %u ;; img_org_y %u ;; img_h %u ;; "
		// 			 "img_w %u\n",
		// 			 img_hdr->offset, img_hdr->org_x, img_hdr->org_y,
		// 			 img_hdr->height, img_hdr->width * 2);

		off += sizeof(struct tim_img_hdr) + img_data_sz;

		char *end = data + off;
		char out_name[255];

		snprintf(out_name, 254 - 4, "0x%08lx", off - (end - start));
		strcat(out_name, ".TIM");

		FILE *out = fopen(out_name, "w");
		if (out == NULL) {
			err = true;
			break;
		}

		ret = fwrite(start, sizeof(char), end - start, out);
		if (ret != end - start) {
			fprintf(stderr, "error writing output to file\n");

			err = true;
			break;
		}

		ret = fclose(out);
		if (ret != 0) {
			perror("could not close file");

			err = true;
			break;
		}
	}

 end:

	free(data);

	ret = fclose(in);
	if (ret != 0) {
		perror("could not close file");
		return EXIT_FAILURE;
	}
	
	if (err) {
		return EXIT_SUCCESS;
	} else {
		return EXIT_FAILURE;
	}
}
