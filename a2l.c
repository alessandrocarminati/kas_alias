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

static char *normalizePath(const char *inputPath, char *outputPath) {
	char *prevToken = NULL;
	char *delimiter = "/";
	char inbuf[MAX_BUF];
	char *token;

	memset(inbuf, 0, MAX_BUF);
	*outputPath = '\0';
	strncpy(inbuf, inputPath, MAX_BUF);
	if (inputPath == NULL || outputPath == NULL || strlen(inputPath) == 0) {
		return NULL;
	}

	token = strtok(inbuf, delimiter);
	while (token != NULL) {
		if (strcmp(token, "..") == 0 && prevToken != NULL) {
			char* pos = strrchr(outputPath, '/');
			if (pos != NULL) {
				*pos = '\0';
			}
		} else if (strcmp(token, ".") != 0) {
			strcat(outputPath, "/");
			strcat(outputPath, token);
		}

		prevToken = token;
		token = strtok(NULL, delimiter);
	}

	return outputPath;
}

static void path_of(const char* fullPath, char* path) {
	const char* lastSlash = strrchr(fullPath, '/');
	char cwd[MAX_BUF];

	if (lastSlash == NULL) {
		getcwd(cwd, sizeof(cwd));
		strcpy(path, cwd);
	} else {
		size_t pathLength = lastSlash - fullPath;
		strncpy(path, fullPath, pathLength);
		path[pathLength] = '\0';
	}
}

static bool file_exists(const char* filePath) {
	FILE* file = fopen(filePath, "r");

	if (file != NULL) {
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

	return 1;
}

const char *remove_subdir(const char *home, const char *f_path)
{
	int i=0;

	while (*(home + i) == *(f_path + i)) i++;
	return strlen(home)!=i?NULL:f_path + i;
}

char *addr2line_get_lines(uint64_t address)
{
	FILE *a2l_stdin, *a2l_stdout;
	char buf[MAX_BUF];


	if (addr2line_pid == -1) {
		printf("addr2line process is not initialized\n");
		return NULL;
	}

	a2l_stdin = fdopen(a2l_in[P_WRITE], "w");
	if (a2l_in == NULL) {
	    printf("Failed to open pipe a2l_in\n");
	    return NULL;
	}

	a2l_stdout = fdopen(a2l_out[P_READ], "r");
	if (a2l_out == NULL) {
		printf("Failed to open pipe a2l_out\n");
		fclose(a2l_stdin);
		return NULL;
	}

	fprintf(a2l_stdin, "%08lx\n", address);
	fflush(a2l_stdin);

	if (fgets(line, sizeof(line), a2l_stdout) == NULL) {
		printf("Failed to read lines from addr2line\n");
		fclose(a2l_stdin);
		fclose(a2l_stdout);
		return NULL;
	}
	if (fgets(line, sizeof(line), a2l_stdout) == NULL) {
		printf("Failed to read lines from addr2line\n");
		fclose(a2l_stdin);
		fclose(a2l_stdout);
		return NULL;
	}

	line[strcspn(line, "\n")] = '\0';
	return normalizePath(line, buf);
}

int addr2line_cleanup()
{
	int status;

	if (addr2line_pid != -1) {
		kill(addr2line_pid, SIGKILL);
		waitpid(addr2line_pid, &status, 0);
		addr2line_pid = -1;
	}

	return 1;
}

const char *get_addr2line(int mode)
{
	if (mode == A2L_DEFAULT)
		return ADDR2LINE;
	return NULL;
}

const char *get_vmlinux(int mode)
{
	if (mode == A2L_DEFAULT)
		return  VMLINUX;
	return NULL;
}
