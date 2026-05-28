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

**High:** Use-after-free in `process_connection` after `close_session(id)`.
After `close_session` frees `curr`, `s` still points to that freed memory:

```c
close_session(id);
printf("Auto-closed internal session %d from %s\n", s->session_id, s->client_ip);
```

This is undefined behavior and can crash or print corrupted data. I’d log before freeing, or copy the needed fields before calling `close_session`.

**High:** `strdup(ip)` is not checked.
If `strdup` fails, `client_ip` becomes `NULL`, but the session is still inserted into the list. Later `printf("%s", s->client_ip)` can crash. I’d check it and free `s` on failure.

**Medium:** `ip` is assumed non-NULL.
Both `strdup(ip)` and `strncmp(ip, "10.", 3)` will crash if a malformed record passes `NULL`. I’d validate `ip` in `create_session` or `process_connection`.

**Medium:** Duplicate `session_id` values are allowed.
`create_session` always prepends a new node, and `close_session(id)` removes only the first matching one. In a monitoring tool, this can leave stale duplicate sessions or close the wrong one. I’d either reject duplicates, update the existing session, or define session IDs as non-unique and close all matches deliberately.

**Medium:** Not thread-safe if records are processed concurrently.
`session_list` is global mutable state with no locking. If this runs in a real network monitor with multiple worker threads, list insertion, traversal, and deletion can race. I’d wrap list access with a mutex or move session ownership into a single event loop.

**Low:** `is_active` is misleading.
It is always set to `1` and never changed. Since closed sessions are removed from the list, `print_active_sessions` does not need the flag. I’d either remove it or change `close_session` semantics to mark inactive instead of freeing.

The first fix I’d make is the use-after-free:

```c
if (strncmp(ip, "10.", 3) == 0) {
    printf("Auto-closed internal session %d from %s\n", s->session_id, s->client_ip);
    close_session(id);
}
```

Then I’d harden allocation:

```c
s->client_ip = strdup(ip);
if (!s->client_ip) {
    free(s);
    return NULL;
}
```
