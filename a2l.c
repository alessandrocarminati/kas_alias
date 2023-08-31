// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "a2l.h"

int addr2line_pid = -1;
int a2l_in[2];
int a2l_out[2];
char line[MAX_BUF];
char vmlinux_path[MAX_BUF];
char addr2line_cmd[MAX_CMD_LEN];
FILE *a2l_stdin, *a2l_stdout;

static char *normalize_path(const char *input_path, char *output_path)
{
	char *prev_token = NULL;
	char *delimiter = "/";
	char inbuf[MAX_BUF] = {0};
	char *token;
	char *pos;

	*output_path = '\0';
	strncpy(inbuf, input_path, MAX_BUF);
	if (!input_path || !output_path || strlen(input_path) == 0)
		return NULL;

	token = strtok(inbuf, delimiter);
	while (token) {
		if (strcmp(token, "..") == 0 && prev_token) {
			pos = strrchr(output_path, '/');
			if (pos)
				*pos = '\0';

		} else if (strcmp(token, ".") != 0) {
			strcat(output_path, "/");
			strcat(output_path, token);
		}

		prev_token = token;
		token = strtok(NULL, delimiter);
	}

	return output_path;
}

static void path_of(const char *full_path, char *path)
{
	const char *last_slash = strrchr(full_path, '/');
	size_t path_length;
	char cwd[MAX_BUF];

	if (!last_slash) {
		if (getcwd(cwd, sizeof(cwd)))
			strcpy(path, cwd);
		else
			strcpy(path, ".");
	} else {
		path_length = last_slash - full_path;
		strncpy(path, full_path, path_length);
		path[path_length] = '\0';
	}
}

static bool file_exists(const char *file_path)
{
	FILE *file;

	file = fopen(file_path, "r");
	if (file) {
		fclose(file);
		return true;
	}
	return false;
}

int addr2line_init(const char *cmd, const char *vmlinux)
{
	if ((!file_exists(cmd)) || (!file_exists(vmlinux))) {
		printf("file not found\n");
		return 0;
	}

	path_of(vmlinux, vmlinux_path);
	if (pipe(a2l_in) == -1) {
		printf("Failed to create pipe\n");
		return 0;
	}

	if (pipe(a2l_out) == -1) {
		printf("Failed to create pipe\n");
		return 0;
	}

	addr2line_pid = fork();
	if (addr2line_pid == -1) {
		printf("Failed to fork process\n");
		close(a2l_in[P_READ]);
		close(a2l_in[P_WRITE]);
		close(a2l_out[P_READ]);
		close(a2l_out[P_WRITE]);
		return 0;
	}

	if (addr2line_pid == 0) {
		dup2(a2l_in[P_READ], 0);
		dup2(a2l_out[P_WRITE], 1);
		close(a2l_in[P_WRITE]);
		close(a2l_out[P_READ]);

		execlp(cmd, cmd, ADDR2LINE_ARGS, vmlinux, NULL);

		printf("Failed to execute addr2line command\n");
		exit(1);
	} else {
		close(a2l_in[P_READ]);
		close(a2l_out[P_WRITE]);
	}

	a2l_stdin = fdopen(a2l_in[P_WRITE], "w");
	if (!a2l_stdin) {
		printf("Failed to open pipe a2l_in\n");
		return 0;
	}

	a2l_stdout = fdopen(a2l_out[P_READ], "r");
	if (!a2l_stdout) {
		printf("Failed to open pipe a2l_out\n");
		fclose(a2l_stdin);
		return 0;
	}

	return 1;
}

const char *remove_subdir(const char *home, const char *f_path)
{
	int i = 0;

	while (home[i] == f_path[i])
		i++;

	return (strlen(home) != i) ? NULL : f_path + i;
}

char *addr2line_get_lines(uint64_t address)
{
	char buf[MAX_BUF];

	fprintf(a2l_stdin, "%08lx\n", address);
	fflush(a2l_stdin);

	if (!fgets(line, sizeof(line), a2l_stdout)) {
		printf("Failed to read lines from addr2line\n");
		return NULL;
	}

	if (!fgets(line, sizeof(line), a2l_stdout)) {
		printf("Failed to read lines from addr2line\n");
		return NULL;
	}

	line[strcspn(line, "\n")] = '\0';
	strncpy(buf, line, MAX_BUF);
	return normalize_path(buf, line);
}

int addr2line_cleanup(void)
{
	int status;

	if (addr2line_pid != -1) {
		kill(addr2line_pid, SIGKILL);
		waitpid(addr2line_pid, &status, 0);
		fclose(a2l_stdin);
		fclose(a2l_stdout);
		addr2line_pid = -1;
	}

	return 1;
}

static char *find_executable(const char *command)
{
	char *path_env = getenv("PATH");
	char *executable_path;
	char *path_copy;
	char *path;
	int n;

	if (!path_env)
		return NULL;

	path_copy = strdup(path_env);
	if (!path_copy)
		return NULL;

	path = strtok(path_copy, ":");
	while (path) {
		n = snprintf(0, 0, "%s/%s", path, command);
		executable_path = (char *)malloc(n + 1);
		snprintf(executable_path, n + 1, "%s/%s", path, command);
		if (access(executable_path, X_OK) == 0) {
			free(path_copy);
			return executable_path;
		}

	path = strtok(NULL, ":");
	free(executable_path);
	executable_path = NULL;
	}

	free(path_copy);
	if (executable_path)
		free(executable_path);
	return NULL;
}

const char *get_addr2line(int mode)
{
	int buf_len = 0;
	char *buf = "";

	switch (mode) {
	case A2L_CROSS:
		buf = getenv("CROSS_COMPILE");
		if (buf) {
			memcpy(addr2line_cmd, buf, strlen(buf));
			buf_len = strlen(buf);
		}
	case A2L_NATIVE_ONLY:
		memcpy(addr2line_cmd + buf_len, ADDR2LINE, strlen(ADDR2LINE));
		buf = find_executable(addr2line_cmd);
		if (buf) {
			memcpy(addr2line_cmd, buf, strlen(buf));
			free(buf);
		}
		return addr2line_cmd;
	case A2L_LLVM:
	default:
		return NULL;
	}
}

char *get_vmlinux(char *input)
{
	const char *match_string1 = ".syms";
	const char *match_string2 = ".tmp_vmlinux.kallsyms";
	char *result = NULL;
	char *match_pos;

	match_pos = strstr(input, match_string1);
	if (!match_pos)
		return NULL;

	match_pos = strstr(input, match_string2);
	if (!match_pos)
		return NULL;

	result = strdup(input);
	match_pos = strstr(result, match_string1);
	*match_pos = '\0';
	return result;
}
