//y
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>

const char* convert_buffer(int signal) {

 static char buffer[20];

    switch (signal) {
  case 1:
   return "SIGHUP";
  case 2:
   return "SIGINT";
  case 3:
   return "SIGQUIT";
  case 4:
   return "SIGILL";
  case 5:
   return "SIGTRAP";
  case 6:
   return "SIGABRT";
  case 7:
   return "SIGBUS";
  case 8:
   return "SIGFPE";
  case 9:
   return "SIGKILL";
  case 11:
   return "SIGSEGV";
  case 13:
   return "SIGPIPE";
  case 14:
   return "SIGALRM";
  case 15:
   return "SIGTERM";
  case 19:
   return "SIGSTOP";

  default:
  sprintf(buffer, "%d", signal);
  return buffer;
    }
}


int main(int argc, char *argv[]) {
    // Check if a test program is specified
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <test_program>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("Process start to fork\n");

    pid_t pid = fork();

    if (pid < 0) {
        // Fork failed
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        printf("I'm the Child Process, my pid = %d\n", getpid());
        printf("Child process start to execute test program:\n");

		char *test_program = argv[1];
        // Execute the test program
		raise(SIGCHLD);
        execvp(test_program, argv + 1);

        // If exec fails
        perror("exec");
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        printf("I'm the Parent Process, my pid = %d\n", getpid());

        int status;
        waitpid(pid, &status, WUNTRACED);
        printf("Parent process receives SIGCHLD signal\n");

        // Check how the child terminated
        if (WIFEXITED(status)) {
            printf("Normal termination with EXIT STATUS = %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("child process get %s signal\n", convert_buffer(WTERMSIG(status)));
        } else if (WIFSTOPPED(status)) {
			printf("child process %s signal\n", convert_buffer(WSTOPSIG(status)));
		}
    }
    return 0;
}
