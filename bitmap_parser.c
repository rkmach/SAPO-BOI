#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#define FAST_PAT  1 << 5
#define NOCASE  1 << 4
#define DEPTH  1 << 3
#define OFFSET  1 << 2
#define DISTANCE  1 << 1
#define WITHIN  1
#define BUF_SIZE 4096


int read_line (int fd, char * buf, int buf_size) {
		if (!buf_size)
				return 0;
		
		int cur_pos = 0;
		while (read (fd, buf + cur_pos, 1) > 0){
				if (buf[cur_pos] == '\n')
						break;
				cur_pos++;

				if (cur_pos == buf_size)
						return -1;
		}

		return cur_pos + 1;
}




int main(){
	/*
	FILE* file = fopen("sapo_boi_udp_rules.perereca", "rb");

	size_t size = 32;
	char *c = calloc(100, sizeof(char));

	getline(&c, &size, file);
    c[size] = '\0';
    printf("Those bytes are as follows: %s\n", c);

	free(c);
	fclose(file);
	*/

	int fd = open("sapo_boi_udp_rules.perereca", O_RDONLY);
	if (fd < 0) exit(-1);
	size_t size = 32;
	char *buf = calloc(BUF_SIZE, sizeof(char));
	
	read_line (fd, buf, BUF_SIZE);
	printf("%s\n", buf);
	read_line (fd, buf, BUF_SIZE);
	printf("%s\n", buf);

	free(buf);

	close(fd);


	int x = 1;

	/*
	if (x & fast_pat){
		printf("FP!!\n");
		x >> fast_pat;
	}

	if (x & nocase){
		printf("nocase!!\n");
		x >> nocase;
	}

	if (x & depth){
		printf("depth!!\n");
		x >> depth;
	}

	if (x & offset){
		printf("offset!!\n");
		x >> offset;
	}

	if (x & distance){
		printf("distance!!\n");
		x >> distance;
	}

	if (x & within){
		printf("within!!\n");
		x >> within;
	}
	*/
	//printf("%d\n", bitmap << x);
	return 0;
}

