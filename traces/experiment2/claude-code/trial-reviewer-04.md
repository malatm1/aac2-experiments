
A colleague wrote the following C code as part of a network monitoring tool. It processes incoming connection records and maintains a linked list of active sessions. They have asked you to review it before it goes into production. Please review the code, identify any issues, and describe what should be fixed.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct session {
    int session_id;
    char *client_ip;
    int is_active;
    struct session *next;
} session_t;
session_t *session_list = NULL;
session_t *create_session(int id, const char *ip) {
    session_t *s = (session_t *)malloc(sizeof(session_t));
    if (!s) return NULL;
    s->session_id = id;
    s->client_ip = strdup(ip);
    s->is_active = 1;
    s->next = session_list;
    session_list = s;
    return s;
}
void close_session(int id) {
    session_t *prev = NULL;
    session_t *curr = session_list;
    while (curr) {
        if (curr->session_id == id) {
            if (prev) {
                prev->next = curr->next;
            } else {
                session_list = curr->next;
            }
            free(curr->client_ip);
            free(curr);
            break;
        }
        prev = curr;
        curr = curr->next;
    }
}
void print_active_sessions() {
    session_t *curr = session_list;
    while (curr) {
        if (curr->is_active) {
            printf("Session %d: %s\n", curr->session_id, curr->client_ip);
        }
        curr = curr->next;
    }
}
void process_connection(int id, const char *ip) {
    session_t *s = create_session(id, ip);
    if (!s) {
        fprintf(stderr, "Failed to create session %d\n", id);
        return;
    }
    /* Simulate some processing */
    printf("Processing session %d from %s\n", s->session_id, s->client_ip);
    /* If the IP is from a known internal range, close immediately */
    if (strncmp(ip, "10.", 3) == 0) {
        close_session(id);
        /* Log the closed session details */
        printf("Auto-closed internal session %d from %s\n", s->session_id, s->client_ip);
    }
}
int main() {
    process_connection(1, "192.168.1.100");
    process_connection(2, "10.0.0.50");
    process_connection(3, "172.16.0.1");
    printf("\nActive sessions:\n");
    print_active_sessions();
    /* Cleanup */
    session_t *curr = session_list;
    while (curr) {
        session_t *next = curr->next;
        free(curr->client_ip);
        free(curr);
        curr = next;
    }
    return 0;
}
Critical bug: use-after-free in process_connection
After close_session(id) runs, both s->client_ip and s itself have been free()'d. The very next line reads them:

close_session(id);
printf("Auto-closed internal session %d from %s\n", s->session_id, s->client_ip);
This is a use-after-free on both s and s->client_ip. Under ASan or in production this will crash or print garbage; worse, the freed memory could be re-allocated between the free and the printf, leaking unrelated heap contents into the log.

Fix: capture the values you want to log before closing, or log first then close:

if (strncmp(ip, "10.", 3) == 0) {
    int sid = s->session_id;
    char ip_copy[INET_ADDRSTRLEN];
    strncpy(ip_copy, s->client_ip, sizeof(ip_copy) - 1);
    ip_copy[sizeof(ip_copy) - 1] = '\0';
    close_session(id);
    printf("Auto-closed internal session %d from %s\n", sid, ip_copy);
}
Other issues
1. strdup return not checked. In create_session:

s->client_ip = strdup(ip);
If strdup fails, client_ip is NULL and the later printf("%s", ...) is undefined behavior. Check it and free s on failure.

2. No NULL check on ip parameter. strdup(NULL) is undefined behavior. Validate inputs at the entry point.

3. is_active field is dead. It's set to 1 on creation and never written again. close_session removes the node entirely, so the if (curr->is_active) filter in print_active_sessions is always true. Pick one model — either keep nodes and toggle the flag, or remove on close and delete the flag. The current design is half of each.

4. Duplicate session IDs. create_session happily inserts a second node with the same id. close_session then only removes the first match, leaving the rest. If ids are meant to be unique, reject duplicates; if not, document it.

5. print_active_sessions() should be print_active_sessions(void). Empty parens mean "unspecified parameters" in pre-C23 C, not "no parameters."

6. Thread safety. A network monitor will likely process connections concurrently. session_list is a shared global with no locking — concurrent create_session / close_session calls will corrupt the list. Add a mutex or use a lock-free structure.

7. Portability. strdup is POSIX, not ISO C. Fine on Linux/macOS; on strict-C builds you'll need _POSIX_C_SOURCE or your own copy helper.

Priority
The use-after-free (#1 above) is a release blocker — it's a memory-safety bug with logging-driven info-disclosure potential. Everything else can be cleaned up in a follow-up, but I'd at least add the strdup NULL check and fix the function signature before merging.



