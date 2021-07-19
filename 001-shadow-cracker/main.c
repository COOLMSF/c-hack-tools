#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_LINE 1024
#define MAX_BUF 200
#define MAX_USER 1024

void check_euid();
unsigned long get_last_index(char *buf, char c);

struct shadow {
	char username[MAX_BUF];
	// char encrypt_method[MAX_BUF];
	char salt[MAX_BUF];
	char encrypted_pass[MAX_LINE];
	int last_pass_change;
	int min_pass_age;
	int max_pass_age;
	int warning_period;
	int inactivity_period;
	int exp_date;
	int unused;
};

int
main(int argc, char *argv[])
{
	if (argc < 3) {
		fprintf(stderr, "usage: %s [-u user-name] "
						"[-f shadow-file] [-d dictionary-file]", argv[0]);
		exit(EXIT_FAILURE);
	}

	check_euid();

	int c;
	char username[MAX_BUF], dict_name[MAX_BUF], shadow_name[MAX_BUF];

	while (1) {
		c = getopt(argc, argv, "u:f:d:");
		if (c == -1)
			break;

		switch (c) {
		case 'u':
			if (optarg)
				strncpy(username, optarg, MAX_BUF);
			break;
		case 'f':
			if (optarg)
				strncpy(shadow_name, optarg, MAX_BUF);
			break;
		case 'd':
			if (optarg)
				strncpy(dict_name, optarg, MAX_BUF);
			break;
		default:
			fprintf(stderr, "usage: %s [-u user-name] "
							"[-f shadow-file] [-d dictionary-file]", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	FILE *fp_shadow, *fp_dict;
	struct shadow user_info[MAX_USER];

	fp_shadow = fopen(shadow_name, "r");
	if (fp_shadow == NULL) {
		perror("fopen shadow file");
		exit(EXIT_FAILURE);
	}

	fp_dict = fopen(dict_name, "r");
	if (fp_dict == NULL) {
		perror("fopen dict file");
		exit(EXIT_FAILURE);
	}

	char *line;
	int k = 0;
	size_t len = 0;
	size_t nread;

	/*
	 * read data from shadow file, store them in shadow structure
	 */
	struct shadow *p = user_info;

	while ((nread = getline(&line, &len, fp_shadow)) != -1 && k < MAX_USER) {
		char *buf;
		int c = 0;
		unsigned long index = 0;
		buf = strtok(line, ":");

		/*
		 * read all fields into shadow structure
		 */
    	while (buf) {
			switch (c) {
			case 0:
				strncpy(p->username, buf, MAX_BUF);
				break;
			case 1:
				/*
				 * this field contains salt and encrypted password
				 */
				index = get_last_index(buf, '$');
				strncpy(p->salt, buf, index);
				strncpy(p->encrypted_pass, buf + index, strlen(buf) - index);
			}

			// next field
			c++;
    	    buf = strtok(NULL, ":");
    	}
		// next user info
		p++;
	}

	free(line);
	fclose(fp_shadow);
	fclose(fp_dict);
	exit(EXIT_FAILURE);
}

void check_euid()
{
	uid_t euid;

	euid = geteuid();
	if (euid != 0) {
		fprintf(stderr, "run as root");
		exit(EXIT_FAILURE);
	}
}

unsigned long get_last_index(char *buf, char c)
{
	unsigned long len = strlen(buf);
	unsigned long index = len;
	char *p = buf + len - 1;

	while (index > 0) {
		if (*p == c)
			break;
		index--;
		p--;
	}

	return index;
}