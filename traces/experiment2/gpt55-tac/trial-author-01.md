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

1. **Use-after-free in `process_connection`**
   After `close_session(id)`, the pointer `s` has been freed. This line dereferences freed memory:

   ```c
   printf("Auto-closed internal session %d from %s\n", s->session_id, s->client_ip);
   ```

   That is undefined behavior and could crash or print garbage. Fix by logging before freeing, or copy the needed fields before calling `close_session`.

2. **`strdup(ip)` is not checked**
   In `create_session`, if `strdup` fails, `client_ip` becomes `NULL`, but the session is still inserted into the list. Later `printf("%s", s->client_ip)` may crash or print implementation-defined output.

   Fix:

   ```c
   s->client_ip = strdup(ip);
   if (!s->client_ip) {
       free(s);
       return NULL;
   }
   ```

3. **No validation for `ip == NULL`**
   `strdup(ip)` and `strncmp(ip, "10.", 3)` both require a non-null pointer. If malformed connection records are possible, validate `ip` before use.

4. **Duplicate session IDs are possible**
   `create_session` always prepends a new session. If two records arrive with the same `id`, `close_session(id)` closes only the first match, and the list can contain ambiguous duplicates. For a monitoring tool, I’d either reject duplicate IDs or update the existing session.

5. **`is_active` is misleading**
   Sessions are removed from the list when closed, so `is_active` is always `1` for every stored session. Either remove the field, or change the lifecycle so closed sessions remain in the list with `is_active = 0`.

6. **Global list is not thread-safe**
   If connection records are processed concurrently, `session_list` updates can race and corrupt the list. Use a mutex or make the session store owned by a single event loop.

**Main Fix**

The immediate memory-safety fix is to avoid using `s` after `close_session`:

```c
if (strncmp(ip, "10.", 3) == 0) {
    printf("Auto-closed internal session %d from %s\n", s->session_id, s->client_ip);
    close_session(id);
}
```

I’d also make `create_session` fail cleanly if either `malloc` or `strdup` fails, and add duplicate-ID handling before inserting the new node.
