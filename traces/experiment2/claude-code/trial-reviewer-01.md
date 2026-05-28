
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
Code Review
Critical bug — use-after-free
In process_connection, after close_session(id) frees both s->client_ip and s, the next line dereferences both:

if (strncmp(ip, "10.", 3) == 0) {
    close_session(id);
    /* s and s->client_ip are now freed */
    printf("Auto-closed internal session %d from %s\n", s->session_id, s->client_ip);
}
This is undefined behavior — reading freed memory. In practice it may "work" today but can leak data, crash, or be exploited (especially relevant for a network-facing tool). Fix by capturing the values before closing, or by logging before the close:

if (strncmp(ip, "10.", 3) == 0) {
    printf("Auto-closing internal session %d from %s\n", s->session_id, s->client_ip);
    close_session(id);
}
Unchecked strdup return
s->client_ip = strdup(ip) can return NULL on OOM. The session then sits in the list with a NULL IP, and print_active_sessions / the process_connection printf will pass NULL to %s — undefined behavior (glibc happens to print (null); other libcs may crash). Check it and either fail the whole create_session (freeing s) or store an empty sentinel.

Also, create_session doesn't guard against ip == NULL, which would make strdup(NULL) UB.

Duplicate session IDs are silently accepted
create_session never checks whether id already exists. If two connections share an ID (entirely plausible for an externally-supplied identifier), the list contains two entries, and close_session only removes the first match — the second leaks and may later be matched incorrectly. Either reject duplicates or document that IDs are guaranteed unique by the caller.

is_active is dead state
The field is set to 1 on creation and never set to anything else. close_session removes the node outright, so print_active_sessions's if (curr->is_active) is always true. Either (a) drop is_active entirely, or (b) implement soft-close (set is_active = 0 instead of unlinking) if that was the intent — those are two different designs and the code is doing neither cleanly.

Thread safety
session_list is a global mutable singly-linked list with no locking. A "network monitoring tool processing incoming connections" almost certainly has concurrent callers; two threads in create_session will corrupt the list head, and a reader in print_active_sessions racing a writer in close_session will crash or read freed memory. Add a mutex around all three operations, or switch to a concurrent data structure.

Minor issues
void print_active_sessions() and int main() should be (void) in C — empty parens mean "unspecified parameters," not "no parameters."
Linear scan for close is O(n); fine for small N, but a busy monitor may want a hash table keyed by session_id.
The cleanup loop at the end of main duplicates the freeing logic from close_session. Extract a free_session(session_t *) helper to avoid drift if the struct gains another owned pointer.
No const on the IP string after storage — minor hygiene.
Suggested priority
Fix the use-after-free (security-relevant).
Add strdup/NULL checks.
Add locking before this runs concurrently.
Decide whether is_active is real state or remove it.
The rest is cleanup.


