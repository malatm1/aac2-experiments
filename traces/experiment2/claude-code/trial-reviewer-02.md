
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
Critical bugs
1. Use-after-free in process_connection (most severe)
if (strncmp(ip, "10.", 3) == 0) {
    close_session(id);
    printf("Auto-closed internal session %d from %s\n", s->session_id, s->client_ip);
}
close_session(id) calls free(curr->client_ip) and free(curr) — which are the same allocations s and s->client_ip point to. The subsequent printf reads freed memory: undefined behavior, likely to read garbage or crash, and on a multi-threaded server it can leak data from a later allocation that reused those bytes.

Fix: capture what you need before closing.

if (strncmp(ip, "10.", 3) == 0) {
    int sid = s->session_id;
    char ip_copy[INET_ADDRSTRLEN];
    snprintf(ip_copy, sizeof(ip_copy), "%s", s->client_ip);
    close_session(id);
    printf("Auto-closed internal session %d from %s\n", sid, ip_copy);
}
Or log before closing.

2. Unchecked strdup return
strdup(ip) can return NULL on OOM. The session is then stored with a NULL client_ip, and print_active_sessions passes it to %s — undefined behavior on most libcs. ip itself being NULL would also crash strdup/strncmp.

Fix: validate ip != NULL at entry; if strdup fails, free s and return NULL.

3. Dead is_active field / inconsistent lifecycle model
is_active is set to 1 at creation and never changed anywhere. close_session removes and frees the node instead of flipping the flag. So print_active_sessions's if (curr->is_active) is always true and just adds noise. Pick one model:

Hard delete (current behavior): remove the is_active field entirely.
Soft delete: have close_session set is_active = 0 and free elsewhere — this also lets you log post-close without UAF.
4. No duplicate-ID protection
create_session blindly prepends. If two connections share an ID (easy with int IDs), close_session only unlinks the first match (the newer one, since it's prepended), leaving the older one orphaned forever. At minimum, scan the list first and reject duplicates, or use a monotonic counter generated inside create_session.

Significant issues
5. Not thread-safe
A network monitor almost certainly handles connections concurrently. session_list is a global mutated without any lock — concurrent create_session/close_session will corrupt the list, leak nodes, or double-free. Wrap accesses in a mutex, or switch to a concurrent data structure.

6. O(n) lookup in close_session
Linear scan is fine for tens of sessions, not for a monitoring tool that may track thousands. A hash table keyed by session ID is the usual fix.

Minor / style
print_active_sessions() and main() use the empty parameter list, which in C means unspecified parameters. Use (void).
(session_t *)malloc(...) cast is unnecessary in C and can hide a missing <stdlib.h> include.
The main cleanup duplicates the free logic from close_session — extract a destroy_session(session_t *) helper and reuse it.
Consider const char * for client_ip once stored, and storing IPs in fixed-size buffers (INET6_ADDRSTRLEN) rather than strdup to avoid per-session heap churn.
Priority for the fix
Bug #1 (UAF) — must fix before production; it's exploitable and will crash under load.
Bug #2 (unchecked strdup) — must fix; trivial.
Bug #5 (thread safety) — required if this runs in any concurrent context; clarify the threading model first.
Bugs #3, #4 — fix the design ambiguity (is_active vs. removal) and decide on ID uniqueness before more code is written against this API.


