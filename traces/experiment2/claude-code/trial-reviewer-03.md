
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
Reviewing the code now.

Critical: use-after-free in process_connection
if (strncmp(ip, "10.", 3) == 0) {
    close_session(id);
    printf("Auto-closed internal session %d from %s\n", s->session_id, s->client_ip);
}
close_session(id) calls free(curr->client_ip) and free(curr) — and curr is s. The very next line reads s->session_id and s->client_ip from freed memory. This is the most serious bug: undefined behavior, and on a network-facing tool it's an exploitable read-after-free.

Fix: capture the values into locals before closing, or just reorder:

if (strncmp(ip, "10.", 3) == 0) {
    printf("Auto-closing internal session %d from %s\n", s->session_id, s->client_ip);
    close_session(id);
}
Other real bugs
strdup return value unchecked. If strdup(ip) returns NULL, client_ip is NULL and the later printf("%s", ...) is UB. Either check and unwind (free(s); return NULL;), or accept that the node is malformed. Same hazard if ip itself is NULL — strdup(NULL) is UB.
is_active is dead state. It's set to 1 at creation and never cleared. close_session removes the node entirely rather than flipping the flag, so if (curr->is_active) in print_active_sessions is always true. Either drop the field, or change close_session to set is_active = 0 rather than unlinking (decide which semantics you actually want — "closed" sessions are presumably interesting for auditing).
No duplicate-ID guard. create_session happily inserts a second node with the same session_id. close_session only removes the first match, leaving the rest. For a session table this is almost certainly wrong — create_session should reject or replace duplicates.
No thread safety. session_list is a global mutated by every connection. A network monitor that processes connections concurrently will corrupt the list. Needs a mutex around create/close/iterate, or a documented single-threaded contract.
Minor
print_active_sessions() and main() should be declared print_active_sessions(void) / main(void) for strict C.
The strncmp(ip, "10.", 3) heuristic will match "10." but also e.g. "10.X" strings that aren't valid IPv4 — fine as a quick classifier, but don't trust it as actual CIDR membership.
Style: cast on malloc is unnecessary in C and can hide a missing <stdlib.h>.
The use-after-free is the only one I'd consider a release blocker; #1–#4 above should also be fixed before this handles real traffic.



