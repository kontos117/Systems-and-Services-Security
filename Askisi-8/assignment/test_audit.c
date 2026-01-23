#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    int i;
    size_t bytes;
    FILE *file;

    /* 10 simple filenames: file_0 ... file_9 */
    char filenames[10][16] = {
        "file_0.txt", "file_1.txt", "file_2.txt", "file_3.txt", "file_4.txt",
        "file_5.txt", "file_6.txt", "file_7.txt", "file_8.txt", "file_9.txt"
    };

    printf("[TEST] Step 1: Creating 10 files...\n");

    /* Step 1: Create several files */
    for (i = 0; i < 10; i++) {
        file = fopen(filenames[i], "w+");
        if (!file) {
            perror("fopen (create)");
            continue;
        }

        /* Write some initial content that depends on the file name */
        bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
        if (bytes != 1) {
            perror("fwrite (initial)");
        }

        fclose(file);
    }

    /* Step 2: Open and modify them under various conditions */
    printf("[TEST] Step 2: Modifying some files...\n");

    /* Append to file_2 */
    file = fopen("file_2.txt", "a");
    if (file) {
        const char *msg = " APPEND_2";
        bytes = fwrite(msg, strlen(msg), 1, file);
        if (bytes != 1)
            perror("fwrite (file_2.txt append)");
        fclose(file);
    } else {
        perror("fopen (file_2.txt append)");
    }

    /* Overwrite file_3, then append again (multiple modifications) */
    file = fopen("file_3.txt", "w");
    if (file) {
        const char *msg = "OVERWRITE_3";
        bytes = fwrite(msg, strlen(msg), 1, file);
        if (bytes != 1)
            perror("fwrite (file_3.txt overwrite)");
        fclose(file);
    } else {
        perror("fopen (file_3.txt overwrite)");
    }

    file = fopen("file_3.txt", "a");
    if (file) {
        const char *msg = " + MORE_3";
        bytes = fwrite(msg, strlen(msg), 1, file);
        if (bytes != 1)
            perror("fwrite (file_3.txt append)");
        fclose(file);
    } else {
        perror("fopen (file_3.txt append)");
    }

    /* Step 3: Generate denied accesses */

    printf("[TEST] Step 3: Generating denied access attempts...\n");

    /* 3a) File-level denial: remove permissions from an existing file */

    /* 6 sus filenames: sus_0 ... sus_5 */
    char susfiles[6][16] = {
        "sus_0.txt", "sus_1.txt", "sus_2.txt", "sus_3.txt", "sus_4.txt",
        "sus_5.txt" 
    };

    for (i = 0; i < 6; i++) {
        file = fopen(susfiles[i], "w+");
        if (!file) {
            perror("fopen (create)");
            continue;
        }
        fclose(file);
    }

    for (i = 0; i < 6; i++) {
        if (chmod(susfiles[i], 0000) != 0) {
            perror(susfiles[i]);
        } else {
            file = fopen(susfiles[i], "r");
            if (!file) {
                perror(susfiles[i]);
            } else {
            /* In case it somehow succeeds, close it */
                fclose(file);
            }
        }
    }


    return 0;
}