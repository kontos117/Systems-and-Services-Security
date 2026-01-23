#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <linux/limits.h>

#define pid_t int



struct log_entry {

	int uid; /* user id (positive integer) */
	pid_t pid; /* process id (positive integer) */

	char *file; /* filename (string) */

	time_t date; /* file access date - utc*/
	time_t time; /* file access time - utc*/

	int operation; /* access type values [0-3] */
	int action_denied; /* is action denied values [0-1] */

	char *filehash; /* file hash - sha256 - evp */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./audit_monitor \n"
		   "Options:\n"
		   "-s, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void list_unauthorized_accesses(FILE *log)
{
	
    char line[4096];

    struct uid_info {
        int uid;
        char *files[256];
        int file_count;
    } seen[256];

    int seen_count = 0;

    while (fgets(line, sizeof(line), log)) {

		//fprintf(stderr,"%d\n", seen_count);

        struct log_entry e;
        memset(&e, 0, sizeof(e));

        char *token = strtok(line, "|");
        while (token) {
			//fprintf(stderr, "%s\n", token);
            if (strncmp(token, "UID=", 4) == 0)
                e.uid = atoi(token + 4);
            else if (strncmp(token, "FILE=", 5) == 0)
                e.file = strdup(token + 5);
            else if (strncmp(token, "DENIED=", 7) == 0)
                e.action_denied = atoi(token + 7);

            token = strtok(NULL, "|");
        }

        // Only count denied actions
        if (e.action_denied != 1) {
            free(e.file);
            continue;
        }

        // --- Find or create UID record ---
        int idx = -1;
        for (int i = 0; i < seen_count; i++) {
            if (seen[i].uid == e.uid) {
                idx = i;
                break;
            }
        }

        if (idx == -1) {
            idx = seen_count++;
            seen[idx].uid = e.uid;
            seen[idx].file_count = 0;
        }

        // --- Check if this file already counted for this UID ---
        int exists = 0;
        for (int i = 0; i < seen[idx].file_count; i++) {
            if (strcmp(seen[idx].files[i], e.file) == 0) {
                exists = 1;
                break;
            }
        }

        // --- Add file if new ---
        if (!exists) seen[idx].files[seen[idx].file_count++] = strdup(e.file);
        
        free(e.file);
		
    }

    // --- Print results ---
    printf("Suspicious users:\n");
    int found = 0;

	
    for (int i = 0; i < seen_count; i++) {
		//fprintf(stderr,"%d\n", seen[i].file_count);
        if (seen[i].file_count > 5) {
            printf("UID=%d (denied accesses to %d distinct files)\n",
                   seen[i].uid, seen[i].file_count);
            found = 1;
        }
    }

    if (!found)
        printf("No suspicious users found.\n");

    // --- free allocated memory ---

    for (int i = 0; i < seen_count; i++)
        for (int j = 0; j < seen[i].file_count; j++)
            free(seen[i].files[j]);

}

void trim_newline(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    if (len > 0 && s[len-1] == '\n') s[len-1] = '\0';
}

void list_file_modifications(FILE *log, char *file_to_scan)
{
    char line[4096];

    struct user_mod {
        int uid;
        int modifications;
        char last_hash[128];
    } users[256] = {0};   // zero-init

    int user_count = 0;
    int unique_modifications = 0;

    // NEW: track distinct hashes for this file
    char distinct_hashes[256][128];
    int distinct_count = 0;

    while (fgets(line, sizeof(line), log)) {
		trim_newline(line);

        struct log_entry e;
        memset(&e, 0, sizeof(e));

        char *token = strtok(line, "|");
        while (token) {
            if (strncmp(token, "UID=", 4) == 0)
                e.uid = atoi(token + 4);
            else if (strncmp(token, "FILE=", 5) == 0)
                e.file = strdup(token + 5);
            else if (strncmp(token, "OP=", 3) == 0)
                e.operation = atoi(token + 3);
            else if (strncmp(token, "HASH=", 5) == 0)
                e.filehash = strdup(token + 5);
            else if (strncmp(token, "DENIED=", 7) == 0)
                e.action_denied = atoi(token + 7);

            token = strtok(NULL, "|");
        }

        // Ignore denied accesses completely
        if (e.action_denied == 1) {
            free(e.file);
            free(e.filehash);
            continue;
        }

        // Match by filename (basename)
        if (!e.file) {
            free(e.filehash);
            continue;
        }

        const char *fname = strrchr(e.file, '/');
        if (fname)
            fname++;
        else
            fname = e.file;

        if (strcmp(fname, file_to_scan) != 0) {
            free(e.file);
            free(e.filehash);
            continue;
        }

        // --- Find or create user entry ---
        int idx = -1;
        for (int i = 0; i < user_count; i++) {
            if (users[i].uid == e.uid) {
                idx = i;
                break;
            }
        }

        if (idx == -1 && user_count < 256) {
            idx = user_count++;
            users[idx].uid = e.uid;
            users[idx].modifications = 0;
            users[idx].last_hash[0] = '\0';
        }

        // --- Detect modification (per user, as before) ---
        int modified = 0;

        if (e.operation == 2) {
            // fwrite => modification
            modified = 1; 
		}

        if (modified) {
            users[idx].modifications++;
            // NOTE: do NOT touch unique_modifications here anymore
        }

        // --- NEW: track distinct hashes globally ---
        if (e.filehash && strcmp(e.filehash, "N/A") != 0) {
            int seen = 0;
            for (int i = 0; i < distinct_count; i++) {
                if (strcmp(distinct_hashes[i], e.filehash) == 0) {
                    seen = 1;
                    break;
                }
            }
            if (!seen && distinct_count < 256) {
				
                strcpy(distinct_hashes[distinct_count++], e.filehash);
				//fprintf(stderr,"%d: New distinct hash: %s\n", distinct_count, e.filehash);
            }
        }

        // --- Update last hash per user ---
        if (e.filehash && strcmp(e.filehash, "N/A") != 0) {
            strcpy(users[idx].last_hash, e.filehash);
        }

        free(e.file);
        free(e.filehash);
    }

    // --- Compute unique modifications from distinct hashes ---
    if (distinct_count > 0)
        unique_modifications = distinct_count;
    else
        unique_modifications = 0;

    // --- Print results ---
    printf("Users who accessed %s:\n", file_to_scan);
    for (int i = 0; i < user_count; i++) {
        printf("UID=%d -> %d modifications\n",
               users[i].uid, users[i].modifications);
    }
    printf("\nTotal unique modifications: %d\n", unique_modifications);
}





int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./tmp/access_audit.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./tmp/access_audit.log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:s")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 's':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
