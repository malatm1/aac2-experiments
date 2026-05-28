
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
Review
There's one critical bug and a handful of smaller issues. I'll go from worst to least bad.

1. Use-after-free in process_connection (critical)
if (strncmp(ip, "10.", 3) == 0) {
    close_session(id);
    printf("Auto-closed internal session %d from %s\n", s->session_id, s->client_ip);
}
close_session(id) calls free(curr->client_ip) and free(curr) — and curr is the same pointer as s. The very next line then dereferences s->session_id and s->client_ip. That's a textbook use-after-free reading freed memory. With session 2 (10.0.0.50) in main, this is hit on every run. It will appear to "work" in toy tests but is undefined behavior — and s->client_ip may point into a freed/reused allocation, so it can crash or print garbage in production.

Fix: capture the values before closing, or log before the free:

if (strncmp(ip, "10.", 3) == 0) {
    printf("Auto-closing internal session %d from %s\n", s->session_id, s->client_ip);
    close_session(id);
}
2. strdup failure is not handled
s->client_ip = strdup(ip);
If strdup returns NULL (OOM), the session is still inserted into the list. print_active_sessions then does printf("%s", NULL), which is UB on most platforms. Either bail out and free s, or use a sentinel — bailing is cleaner:

s->client_ip = strdup(ip);
if (!s->client_ip) { free(s); return NULL; }
Also: strdup(NULL) is UB, so guard the ip parameter (or document the contract).

3. is_active is dead state
The field is set to 1 on creation and never written again — close_session removes the node entirely. So the if (curr->is_active) check in print_active_sessions can never be false. Pick one model and commit to it: either keep nodes around and flip is_active = 0 on close (tombstones, useful for audit/logging), or drop the field. Right now it looks like a half-finished design.

4. Duplicate session IDs are silently allowed
create_session doesn't check whether id already exists. Two sessions with the same ID will both be inserted; close_session only removes the first match. For a session table this is almost certainly wrong — either reject duplicates or document it.

5. Thread safety
session_list is a process-global mutable linked list with no synchronization. A network monitoring tool that processes "incoming connection records" is exactly the kind of code that gets called from multiple threads or signal handlers. If concurrency is in scope, this needs a mutex (or a lock-free design). Worth confirming the call model with your colleague.

6. Minor
int main() and print_active_sessions() — use (void) in C to mean "no args".
close_session returns nothing; callers can't tell if the ID was found. Returning int (or bool) lets the auto-close path detect a logic bug instead of silently no-op'ing.
Linear scan in close_session is O(n). Fine for tens of sessions, not for a busy monitor — consider a hash table if session counts grow.
Suggested priority
Block on #1 and #2 before this merges. #3 and #4 are design questions to raise with the author. #5 depends on the deployment model — ask before assuming. #6 is polish.



