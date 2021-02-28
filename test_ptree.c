#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "/usr/src/linux-5.4.59/include/linux/prinfo.h"

#define DEFAULT_NR_ARG 100
int main(int argc, char **argv)
{
	struct prinfo *buf;
	int nr;
	int rc;

	if (argc <= 1)
		nr = DEFAULT_NR_ARG;
	else {
		if (is_number(argv[1]))
			nr = atoi(argv[1]);
		else
			nr = DEFAULT_NR_ARG;
	}

	buf = calloc(nr, sizeof(struct prinfo));
	if (buf == NULL) {
		printf("Could not allocate buffer\n");
		exit(-1);
	}

	rc = syscall(548, buf, &nr);

	/*if (rc < 0) {
		perror("ptree!");
		return -1;
	}*/

	print_tree(buf, nr);

	free(buf);
	return 0;
}

void print_tree(struct prinfo *tree, const int size)
{
	int id_stack[size];
	id_stack[0] = 0;
	int num_tabs = 0;
	int i = 0;
	for (i = 0; i < size; i++) {
		while (tree[i].parent_pid != id_stack[num_tabs])
			num_tabs--;

		print_prinfo(num_tabs, tree[i]);
		num_tabs++;
		id_stack[num_tabs] = tree[i].pid;
	}
}

void print_prinfo(int count, struct prinfo p)
{
	char returned[count+1];
	int i = 0;
	for (i = 0; i < count; ++i)
		returned[i] = '\t';
	returned[count] = '\0';
	printf("%s,%d,%lld,%d,%d,%d,%lld\n", p.comm, p.pid, p.state,
  	p.parent_pid, p.first_child_pid, p.next_sibling_pid, p.uid);
}

int is_number(char *string)
{
	int i = 0;

	if (string == NULL)
		return 0;

	for (; string[i] != '\0'; ++i) {
		if (!isdigit(string[i]))
			return 0;
	}
	return 1;
}
