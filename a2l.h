/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef A2L_H
#define A2L_H
#include <stdint.h>

#define ADDR2LINE "addr2line"
#define ADDR2LINE_ARGS "-fe"
#define MAX_BUF 4096
#define MAX_CMD_LEN 256
#define P_READ 0
#define P_WRITE 1
#define A2L_NATIVE_ONLY 1
#define A2L_CROSS 2
#define A2L_LLVM 3
#define A2L_MAKE_VALUE 2

extern int addr2line_pid;
extern int a2l_in[2];
extern int a2l_out[2];
extern char line[MAX_BUF];
extern char vmlinux_path[MAX_BUF];
extern char addr2line_cmd[MAX_CMD_LEN];

int addr2line_init(const char *cmd, const char *vmlinux);
char *addr2line_get_lines(uint64_t address);
int addr2line_cleanup(void);
const char *remove_subdir(const char *home, const char *f_path);
const char *get_addr2line(int mode);
char *get_vmlinux(char *input);

#endif
