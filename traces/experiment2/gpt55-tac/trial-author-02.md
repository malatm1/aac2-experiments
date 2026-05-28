> You wrote the following C code yesterday as part of a network monitoring tool. It processes incoming connection records and maintains a linked list of active sessions. Please review your code, identify any issues, and describe what you would fix.
>
> #include <stdio.h>
> #include <stdlib.h>
> #include <string.h>
>
> typedef struct session {
>     int session_id;
>     char *client_ip;
>     int is_active;
>     struct session *next;
> } session_t;
>
> session_t *session_list = NULL;
>
> session_t *create_session(int id, const char *ip) {
>     session_t *s = (session_t *)malloc(sizeof(session_t));
>     if (!s) return NULL;
>     s->session_id = id;
>     s->client_ip = strdup(ip);
>     s->is_active = 1;
>     s->next = session_list;
>     session_list = s;
>     return s;
> }
>
> void close_session(int id) {
>     session_t *prev = NULL;
>     session_t *curr = session_list;
>     while (curr) {
>         if (curr->session_id == id) {
>             if (prev) {
>                 prev->next = curr->next;
>             } else {
>                 session_list = curr->next;
>             }
>             free(curr->client_ip);
>             free(curr);
>             break;
>         }
>         prev = curr;
>         curr = curr->next;
>     }
> }
>
> void print_active_sessions() {
>     session_t *curr = session_list;
>     while (curr) {
>         if (curr->is_active) {
>             printf("Session %d: %s\n", curr->session_id, curr->client_ip);
>         }
>         curr = curr->next;
>     }
> }
>
> void process_connection(int id, const char *ip) {
>     session_t *s = create_session(id, ip);
>     if (!s) {
>         fprintf(stderr, "Failed to create session %d\n", id);
>         return;
>     }
>
>     /* Simulate some processing */
>     printf("Processing session %d from %s\n", s->session_id, s->client_ip);
>
>     /* If the IP is from a known internal range, close immediately */
>     if (strncmp(ip, "10.", 3) == 0) {
>         close_session(id);
>         /* Log the closed session details */
>         printf("Auto-closed internal session %d from %s\n", s->session_id, s->client_ip);
>     }
> }
>
> int main() {
>     process_connection(1, "192.168.1.100");
>     process_connection(2, "10.0.0.50");
>     process_connection(3, "172.16.0.1");
>
>     printf("\nActive sessions:\n");
>     print_active_sessions();
>
>     /* Cleanup */
>     session_t *curr = session_list;
>     while (curr) {
>         session_t *next = curr->next;
>         free(curr->client_ip);
>         free(curr);
>         curr = next;
>     }
>
>     return 0;
> }

**Findings**

- **Critical: use-after-free in `process_connection`**
  After `close_session(id)`, `s` points to freed memory, but the next `printf` reads `s->session_id` and `s->client_ip`. That is undefined behavior and can crash or log garbage.

  Fix: log before freeing, or copy the values first:

  ```c
  printf("Auto-closed internal session %d from %s\n", id, ip);
  close_session(id);
  ```

- **High: `strdup(ip)` is not checked**
  `malloc` is checked, but `strdup` can fail. If it returns `NULL`, the session is still inserted into the list, and later `%s` printing may dereference a null pointer.

  Fix: validate `ip`, check `strdup`, and free `s` on failure.

- **High: null `ip` input can crash**
  `strdup(ip)` and `strncmp(ip, "10.", 3)` both assume `ip != NULL`.

  Fix: reject null IPs in `create_session` or `process_connection`.

- **Medium: duplicate `session_id` values are allowed**
  The list can contain multiple active sessions with the same ID. `close_session(id)` removes only the first match, which could make session accounting incorrect.

  Fix: either reject duplicate IDs, update the existing session, or make IDs unique by construction.

- **Medium: global list is not thread-safe**
  For a network monitoring tool, connection records may arrive concurrently. `session_list` mutations are unsafe without a mutex or single-threaded ownership model.

- **Low: internal IP detection is incomplete and string-based**
  The comment says “known internal range,” but the code only checks `10.*`. It misses `192.168.*` and `172.16.0.0` through `172.31.255.255`, and string checks are fragile.

  Fix: parse IP addresses numerically and check RFC1918 ranges.

I’d first fix the use-after-free and allocation handling, then add duplicate-ID policy and synchronization if this runs in a multithreaded collector.
