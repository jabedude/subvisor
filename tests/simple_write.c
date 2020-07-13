void _start() {

    char *hello = "Hello, World\n";
    int hello_size = 13;
    int ret = 0;

    /* main body of program: call main(), etc */
    //asm("mov $1,%rax;"
    //    "mov $1,%rdi;"
    //    "lea "
    //    "syscall");
    asm volatile
    (
        "movl $1, %%eax\n\t"
        "movl $1, %%edi\n\t"
        "movq %1, %%rsi\n\t"
        "movl %2, %%edx\n\t"
        "syscall"
        : "=a"(ret)
        : "g"(hello), "g"(hello_size)
        : "%rdi", "%rsi", "%rdx", "%rcx", "%r11", "memory"
    );

    /* exit system call */
    asm("mov $60,%rax; mov $0,%rdi; syscall");
}
