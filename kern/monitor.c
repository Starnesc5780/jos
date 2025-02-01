// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line

int mon_show(int argc, char **argv, struct Trapframe *tf);

struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

// LAB 1: add your command to here...
static struct Command commands[] = {
    { "help", "Display this list of commands", mon_help },
    { "kerninfo", "Display information about the kernel", mon_kerninfo },
    { "showmappings", "Display page mappings in a given range", mon_showmappings },
    { "setperm", "Set new permissions for a virtual page", mon_setperm },
    { "dumpmem", "Dump memory contents from virtual or physical addresses", mon_dumpmem },
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

//Extra Cedit Functions

int mon_showmappings(int argc, char **argv, struct Trapframe *tf) {

    if (argc != 3) {

        cprintf("Usage: showmappings [start_va] [end_va]\n");
        return 0;
    }
	
    uintptr_t start = strtol(argv[1], NULL, 0);
    uintptr_t end = strtol(argv[2], NULL, 0);
    show_mappings(start, end);
    return 0;
}

int mon_setperm(int argc, char **argv, struct Trapframe *tf) {

    if (argc != 3) {

        cprintf("Usage: setperm [va] [perm]\n");
        return 0;
    }

    uintptr_t va = strtol(argv[1], NULL, 0);
    int new_perm = strtol(argv[2], NULL, 0);
    set_page_permissions(va, new_perm);
    return 0;
}

int mon_dumpmem(int argc, char **argv, struct Trapframe *tf) {

    if (argc != 4) {

        cprintf("Usage: dumpmem [va/pa] [size] [0=va, 1=pa]\n");
        return 0;
    }

    uintptr_t addr = strtol(argv[1], NULL, 0);
    size_t size = strtol(argv[2], NULL, 0);
    int is_physical = strtol(argv[3], NULL, 0);
    dump_memory(addr, size, is_physical);
    return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
    cprintf("Stack backtrace:\n");

    //get current base pointer
    uint32_t *ebp = (uint32_t *)read_ebp();

    while (ebp) {
		
		//return address is above saved EBP
        uint32_t eip = ebp[1];
        struct Eipdebuginfo info;

        //print EBP, EIP, and first 5 args
        cprintf("  ebp %08x  eip %08x  args", (uint32_t)ebp, eip);
        for (int i = 2; i < 7; i++) {

            cprintf(" %08x", ebp[i]);
        }

        cprintf("\n");

        //fetch debugging information for EIP
        if (debuginfo_eip(eip, &info) == 0) {

            cprintf("         %s:%d: %.*s+%d\n",
                    info.eip_file, info.eip_line,
                    info.eip_fn_namelen, info.eip_fn_name,
                    eip - info.eip_fn_addr);

        } 
		
		else {
			
            cprintf("         <unknown function>\n");
        }

        // Move to the previous stack frame
        ebp = (uint32_t *)ebp[0];
    }

    return 0;
}



int
mon_show(int argc, char **argv, struct Trapframe *tf)
{
	// Color codes retrieved from ChatGPT (Original Prompt: 
	// "How to use ANSI escape color codes in C print statements")
	const char *red = "\033[31m";
    const char *green = "\033[32m";
	const char *yellow = "\033[33m";
    const char *blue = "\033[34m";
	const char *magenta = "\033[35m";
    const char *reset = "\033[0m";
	//ASCII art design from ChatGPT (Prompt: "Draw simple ASCII 
	// art (house) for C language print")
    cprintf("%s  ^  %s\n", red, reset);
    cprintf("%s / \\ %s\n", green, reset);
    cprintf("%s/   \\%s\n", blue, reset);
    cprintf("%s|   |%s\n", yellow, reset);
    cprintf("%s|___|%s\n", magenta, reset);
	return 0;
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}