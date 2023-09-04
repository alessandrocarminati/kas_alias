#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf.h"

void free_cfg(struct conf *cfg)
{
	int i;

	if (!cfg)
		return;

	for (i = 0; i < cfg->args_free_cnt; i++)
		free(cfg->args_free[i]);

	free(cfg);
}

void conf_error(char *exe_name, struct conf *config)
{
	printf("Usage: %s options\n\t-a  addr2line command\n\t-v  vmlinux\n\t-n  nm data\n\t -o out file", exe_name);
}

static void add_cfg_itm(struct conf *config, char **field, char **argv, int *i){
	*field = strdup(argv[ (*i) + 1]);
	config->args_free[config->args_free_cnt++] = *field;
	*i = *i +1;
}

struct conf *parse_command_line(int argc, char **argv)
{
	struct conf *config = malloc(sizeof(struct conf));
	int i;

	if (config == NULL) {
		return NULL;
	}


	config->addr2line_cmd = NULL;
	config->vmlinux = NULL;
	config->nm_data = NULL;
	config->verbose = 0;
	config->args_free_cnt = 0;
	memset(config->args_free, 0, sizeof(config->args_free));

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
			add_cfg_itm(config, &config->addr2line_cmd, argv, &i);
//			config->addr2line_cmd = strdup(argv[i + 1]);
//			config->args_free[config->args_free_cnt++] = config->addr2line_cmd;
//			i++;
		} else if (strcmp(argv[i], "-v") == 0 && i + 1 < argc) {
			add_cfg_itm(config, &config->vmlinux, argv, &i);
//			config->vmlinux = strdup(argv[i + 1]);
//			config->args_free[args_free_cnt++] = config->vmlinux;
//			i++;
		} else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
			add_cfg_itm(config, &config->nm_data, argv, &i);
//			config->nm_data = strdup(argv[i + 1]);
//			i++;
		} else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
			add_cfg_itm(config, &config->out_file, argv, &i);
//			config->out_file = strdup(argv[i + 1]);
//			i++;
		} else if (strcmp(argv[i], "--verbose") == 0) {
			config->verbose = 1;
		} else {
			free_cfg(config);
			return NULL;
		}
	}

	if (!config->addr2line_cmd || !config->vmlinux ||
	    !config->nm_data || !config->out_file) {
		free_cfg(config);
		return NULL;
	}

	return config;
}
