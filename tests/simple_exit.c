void _start() {

    /* main body of program: call main(), etc */

    /* exit system call */
    asm("mov $60,%rax; mov $0,%rdi; syscall");
}
