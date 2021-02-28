#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/uaccess.h>

#define PID_MAX 8388608

#define is_thread(proc) ((proc)->group_leader->pid != (proc)->pid)

static struct task_struct *next_sibling(struct task_struct *task)
{
	struct task_struct *sibling;

	if (list_empty(&task->sibling))
		return NULL;

	sibling = list_entry(task->sibling.next, struct task_struct, sibling);

	if (sibling->pid == PID_MAX || sibling->pid == 0)
		return NULL;

	if (is_thread(sibling))
		return next_sibling(sibling);

	return sibling;
}

static struct task_struct *first_child(struct task_struct *task)
{
	struct task_struct *child;

	if (list_empty(&task->children))
		return NULL;

	child = list_entry(task->children.next, struct task_struct, sibling);

	if (is_thread(child))
		return next_sibling(child);

	return child;
}

static struct task_struct *dfs_next_task(struct task_struct *task)
{
	struct task_struct *child;
	struct task_struct *ancestor;
	struct task_struct *relative;

	child = first_child(task);

	if (child != NULL)
		return child;

	ancestor = task;

	while (ancestor != &init_task) {
		relative = next_sibling(ancestor);
		if (relative != NULL)
			return relative;
		ancestor = ancestor->parent;
	}

	return NULL;
}

static void set_prinfo(struct prinfo *pr, struct task_struct *task, int index)
{
	struct task_struct *child, *sibling;

	if (task == NULL) {
		pr_err("task is NULL %d\n", index);
		return;
	}

	pr[index].state = task->state;
	pr[index].pid = task->pid;
	pr[index].parent_pid = task->parent->pid;
	pr[index].uid = task->cred->uid.val;
	strncpy(pr[index].comm , task->comm,16);// task_struct->comm will be less then 16 char	
	pr[index].next_sibling_pid = 0;
	pr[index].first_child_pid = 0;

	child = first_child(task);
	sibling = next_sibling(task);

	if (child != NULL)
		pr[index].first_child_pid = child->pid;

	if (sibling != NULL)
		pr[index].next_sibling_pid = sibling->pid;
}

static int populate_prinfo(struct prinfo *pr, int n)
{
	int index = 0;
	struct task_struct *task = &init_task;

	while (task != NULL) {
		if (index < n)
			set_prinfo(pr, task, index);
		index++;
		task = dfs_next_task(task);
	}

	return index;
}

SYSCALL_DEFINE2(ptree, struct prinfo __user *, buf, int __user *, nr)
{
	int knr, nentries;
	struct prinfo *kbuf;

	if (buf == NULL || nr == NULL)
		return -EINVAL;

	if (!access_ok( nr, sizeof(int)))
		return -EFAULT;

	if (copy_from_user(&knr, nr, sizeof(int)))
		return -EFAULT;

	if (knr < 1)
		return -EINVAL;
	
	if (!access_ok( buf, knr * sizeof(struct prinfo)))
		return -EFAULT;

	kbuf = kmalloc(sizeof(struct prinfo) * knr, GFP_KERNEL);

	read_lock(&tasklist_lock);

	nentries = populate_prinfo(kbuf, knr);

	read_unlock(&tasklist_lock);

	if (nentries < 0)
		return -EFAULT;

	if (nentries < knr)
		knr = nentries;

	if (copy_to_user(buf, kbuf, sizeof(struct prinfo) * knr))
		pr_warning("could not copy prinfo buffer to user\n");
	if (copy_to_user(nr, &knr, sizeof(int)))
		pr_warning("could not copy nr integer to user\n");

	kfree(kbuf);

	return nentries;
}
