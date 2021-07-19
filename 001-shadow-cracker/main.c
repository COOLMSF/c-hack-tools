#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_LINE 1024
#define MAX_BUF 200
#define MAX_USER 1024

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

void check_euid();
unsigned long get_last_index(char *buf, char c);
int crack_pass(char *salt, char *shadow_pass, char *dict_pass);

int main(int argc, char *argv[])
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

	// n users
	while ((nread = getline(&line, &len, fp_shadow)) != -1 && k < MAX_USER) {
		char *buf;
		int c = 0;
		unsigned long index = 0;

		k++;
		buf = strtok(line, ":");

		// mark:$6$.n.:17736:0:99999:7:::
		// [--] [----] [---] - [---] ----
		// |      |      |   |   |   |||+-----------> 9. Unused
		// |      |      |   |   |   ||+------------> 8. Expiration date
		// |      |      |   |   |   |+-------------> 7. Inactivity period
		// |      |      |   |   |   +--------------> 6. Warning period
		// |      |      |   |   +------------------> 5. Maximum password age
		// |      |      |   +----------------------> 4. Minimum password age
		// |      |      +--------------------------> 3. Last password change
		// |      +---------------------------------> 2. Encrypted Password
		// +----------------------------------------> 1. Username
		// see, https://linuxize.com/post/etc-shadow-file/

		/*
		 * read all fields into shadow structure
		 */
    	while (buf) {
			switch (c) {
			// username
			case 0:
				strncpy(p->username, buf, MAX_BUF);
				*(p->username + strlen(p->username)) = '\0';
				break;
			// salt and encrypted password
			case 1:
				/*
				 * this field contains salt and encrypted password
				 */
				if (strcmp("!!", buf) == 0 || strcmp("!*", buf) == 0)
					break;

				index = get_last_index(buf, '$');
				// salt
				strncpy(p->salt, buf, index);
				*(p->salt + strlen(p->salt)) = '\0';

				// encrypted password
				strncpy(p->encrypted_pass, buf + index, strlen(buf) - index);
				*(p->encrypted_pass + strlen(p->encrypted_pass)) = '\0';
				break;
			// get last password change field
			case 2:
				p->last_pass_change = atoi(buf);
				break;
			case 3:
				p->min_pass_age = atoi(buf);
				break;
			case 4:
				p->max_pass_age = atoi(buf);
				break;
			case 5:
				p->warning_period = atoi(buf);
				break;
			case 6:
				p->inactivity_period = atoi(buf);
			case 7:
				p->exp_date = atoi(buf);
				break;
			case 8:
				p->unused = atoi(buf);
				break;
			default:
				break;
			}

			// next field
			c++;
    	    buf = strtok(NULL, ":");
    	}
    	// printf("username:%s\t salt:%s\t encrypted_pass:%s\t "
		// 	   "last_pass_change:%d\t min_pass_age:%d\t max_pass_age:%d\t warning_peroid:%d\t int_pero:%d\n",
		// 	   p->username, p->salt, p->encrypted_pass, p->last_pass_change, p->min_pass_age, p->max_pass_age,
		// 	   p->warning_period, p->inactivity_period);

		// next user info
		p++;
	}
	fclose(fp_shadow);

	// for every user
	for (int i = 0; i < MAX_USER; i++) {
		char* dict_pass;

		// try every passowrd
		while ((nread = getline(&dict_pass, &len, fp_dict)) != -1) {
			// remove '\n' at the end of dict_pass
			*(dict_pass + strlen(dict_pass) - 1) = '\0';
			if (crack_pass(user_info[i].salt, user_info[i].encrypted_pass, dict_pass)) {
				printf("PASS FOUND!!!\nusername:%s pass:%s\n", user_info[i].username, dict_pass);
			}
		}
		rewind(fp_dict);
	}

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

int crack_pass(char *salt, char *shadow_pass, char *dict_pass)
{
	char *encrypted_pass;
	char s[MAX_LINE] = { 0 };

	if (strcmp(salt, "") == 0 || strcmp(shadow_pass, "") == 0
	|| strcmp(dict_pass, "") == 0)
		return 0;

	encrypted_pass = crypt(dict_pass, salt);

	strcat(s, salt);
	strcat(s, shadow_pass);

	// return (strcmp(encrypted_pass, shadow_pass) == 0) ? 1 : 0;
	if (strcmp(encrypted_pass, s) == 0)
		return 1;
	else
		return 0;
}