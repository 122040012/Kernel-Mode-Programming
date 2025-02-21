//y
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/delay.h>
#include <linux/pid.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/uaccess.h>
#include <linux/wait.h>  //add WUNTRACED WEXITED

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Filbert Hamijoyo");
MODULE_DESCRIPTION("Kernel module to fork a process and handle signals");

struct wait_opts {
 enum pid_type wo_type;
 int wo_flags;
 struct pid *wo_pid;

 struct waitid_info *wo_info;
 int wo_stat;
 struct rusage *wo_rusage;

 wait_queue_entry_t child_wait;
 int notask_error;
};

struct signal_info {
    const char *name;
    const char *description;
};

extern int do_execve(struct filename *filename,
       const char __user *const __user *__argv,
       const char __user *const __user *__envp);
extern void __noreturn do_exit(long code);
extern long do_wait(struct wait_opts *wo);
extern struct filename *getname_kernel(const char *filename);
extern pid_t kernel_clone(struct kernel_clone_args *kargs);

void my_wait(pid_t pid);
int my_exec(void);
int my_fork(void *data);

EXPORT_SYMBOL(my_wait);
EXPORT_SYMBOL(my_exec);



const char **get_signal_info(int signum) {
    static const char *signal_info[2];

    switch (signum) {
        case SIGHUP:
            signal_info[0] = "SIGHUP";
            signal_info[1] = "Hangup detected on controlling terminal";
            break;
        case SIGINT:
            signal_info[0] = "SIGINT";
            signal_info[1] = "Interrupt from keyboard";
            break;
        case SIGQUIT:
            signal_info[0] = "SIGQUIT";
            signal_info[1] = "Quit from keyboard";
            break;
        case SIGILL:
            signal_info[0] = "SIGILL";
            signal_info[1] = "Illegal Instruction";
            break;
        case SIGTRAP:
            signal_info[0] = "SIGTRAP";
            signal_info[1] = "Trace/breakpoint trap";
            break;
        case SIGABRT:
            signal_info[0] = "SIGABRT";
            signal_info[1] = "Abort signal from abort(3)";
            break;
        case SIGBUS:
            signal_info[0] = "SIGBUS";
            signal_info[1] = "Bus error (bad memory access)";
            break;
        case SIGFPE:
            signal_info[0] = "SIGFPE";
            signal_info[1] = "Floating point exception";
            break;
        case SIGKILL:
            signal_info[0] = "SIGKILL";
            signal_info[1] = "Kill signal";
            break;
        case SIGSEGV:
            signal_info[0] = "SIGSEGV";
            signal_info[1] = "Invalid memory reference";
            break;
        case SIGPIPE:
            signal_info[0] = "SIGPIPE";
            signal_info[1] = "Broken pipe: write to pipe with no readers";
            break;
        case SIGALRM:
            signal_info[0] = "SIGALRM";
            signal_info[1] = "Timer signal from alarm(2)";
            break;
        case SIGTERM:
            signal_info[0] = "SIGTERM";
            signal_info[1] = "Termination signal";
            break;
        case SIGSTOP:
            signal_info[0] = "SIGSTOP";
            signal_info[1] = "Stop process";
            break;
        default:
            signal_info[0] = "UNKNOWN";
            signal_info[1] = "Unknown signal";
            break;
    }

    return signal_info;
}

void my_wait(pid_t pid) {
    int stat;
    long wait_ret;
    struct wait_opts wo;
    struct pid *wo_pid = NULL;
    enum pid_type type;
    const char **signal;

    type = PIDTYPE_PID;
    wo_pid = find_get_pid(pid);
    if (!wo_pid) {
        printk(KERN_INFO "[program2] : Failed to find PID %d\n", pid);
        return;
    }

    wo.wo_type = type;
    wo.wo_flags = WUNTRACED | WEXITED;
    wo.wo_pid = wo_pid;
    wo.wo_info = NULL;
    wo.wo_stat = (int __user *)&stat;
    wo.wo_rusage = NULL;

    do {
        wait_ret = do_wait(&wo);
    } while (wait_ret == -EINTR);

    int status;
    status = wo.wo_stat;


        if (status == 0) {
            printk(KERN_INFO "[program 2] : SIGCHLD");
            printk(KERN_INFO "[program 2] : Child process terminated normally with status %d\n", status);
        }
        else if (status >= 1 && status <= 139) {
            if(status > 128){
                status -=128;
            }
            signal = get_signal_info(status);
            printk(KERN_INFO "[program 2] : get %s signal\n", signal[0]);
            printk(KERN_INFO "[program 2] : Child process %s\n", signal[1]);
            printk(KERN_INFO "[program 2] : The return signal is %d\n", status);
        } else{
            printk("ERROR");
        }

    put_pid(wo_pid);

    return;
}

int my_exec(void) {
    const char path[] = "/tmp/test"; 
    struct filename *file;
    const char *const argv[] = {path, NULL, NULL};
    const char *const envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
    int exec_ret;

    file = getname_kernel(path);
    if (IS_ERR(file)) {
        printk(KERN_INFO "[program2] : getname_kernel failed for path %s\n", path);
        return PTR_ERR(file);
    }

    printk(KERN_INFO "[program2] : Child process");
    exec_ret = do_execve(file, argv, envp);
    if (exec_ret < 0) {
        printk(KERN_INFO "[program2] : do_execve failed with error %d\n", exec_ret);
    }

    return exec_ret;
}

int my_fork(void *data) {
    pid_t child_pid;
    int i;

    struct kernel_clone_args clone_args = {
        .flags = SIGCHLD,
        .pidfd = NULL,
        .child_tid = NULL,
        .parent_tid = NULL,
        .exit_signal = SIGCHLD,
        .stack = (unsigned long)&my_exec,
        .stack_size = 0,
        .tls = 0
    };

    struct k_sigaction *k_action = &current->sighand->action[0];
        for (i = 0; i < _NSIG; i++) {
        k_action->sa.sa_handler = SIG_DFL;
        k_action->sa.sa_flags = 0;
        k_action->sa.sa_restorer = NULL;
        sigemptyset(&k_action->sa.sa_mask);
        k_action++;
    }

    child_pid = kernel_clone(&clone_args);

    if (child_pid == 0) {
        // In child process
        my_exec(); // Execute the test program
    }
    else if (child_pid > 0){
        // In parent process
        printk(KERN_INFO "[program2] : The child process has pid = %d\n", child_pid);
        printk(KERN_INFO "[program2] : This is the parent process, pid = %d\n", current->pid);
        my_wait(child_pid); // Wait for child to terminate
    } else{
        printk(KERN_INFO "ERROR");
    }

    return 0;
}

// Module initialization function
static int __init program2_init(void) {
    struct task_struct *task;

    printk(KERN_INFO "[program2] : module_init\n");
    printk(KERN_INFO "[program2] : module_init create kthread start\n");

    // Create a kernel thread to run my_fork
    task = kthread_run(my_fork, NULL, "program2_kthread");
    if (IS_ERR(task)) {
        printk(KERN_INFO "[program2] : Failed to create kthread\n");
        return PTR_ERR(task);
    }

    printk(KERN_INFO "[program2] : module_init kthread start\n");
    wake_up_process(task);

    return 0;
}

// Module exit function
static void __exit program2_exit(void) {
    printk(KERN_INFO "[program2] : module_exit\n");
}

module_init(program2_init);
module_exit(program2_exit);
