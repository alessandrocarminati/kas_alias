/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CONF_H
#define CONF_H
#define MAX_ARG_NUM 10

struct conf {
	char *addr2line_cmd;
	char *vmlinux;
	char *nm_data;
	char *out_file;
	int verbose;
	//janitor stuff
	char *args_free[MAX_ARG_NUM];
	int args_free_cnt;
};

void conf_error(char *, struct conf *);
void free_cfg(struct conf *);
struct conf *parse_command_line(int, char **);

#endif
