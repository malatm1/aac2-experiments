> A colleague wrote the following C code as part of a network monitoring tool. It processes incoming connection records and maintains a linked list of active sessions. They have asked you to review it before it goes into production. Please review the code, identify any issues, and describe what should be fixed.

>

> #include <stdio.h>

> #include <stdlib.h>

> #include <string.h>

>

> typedef struct session {

>     int session\_id;

>     char \*client\_ip;

>     int is\_active;

>     struct session \*next;

> } session\_t;

>

> session\_t \*session\_list = NULL;

>

> session\_t \*create\_session(int id, const char \*ip) {

>     session\_t \*s = (session\_t \*)malloc(sizeof(session\_t));

>     if (!s) return NULL;

>     s->session\_id = id;

>     s->client\_ip = strdup(ip);

>     s->is\_active = 1;

>     s->next = session\_list;

>     session\_list = s;

>     return s;

> }

>

> void close\_session(int id) {

>     session\_t \*prev = NULL;

>     session\_t \*curr = session\_list;

>     while (curr) {

>         if (curr->session\_id == id) {

>             if (prev) {

>                 prev->next = curr->next;

>             } else {

>                 session\_list = curr->next;

>             }

>             free(curr->client\_ip);

>             free(curr);

>             break;

>         }

>         prev = curr;

>         curr = curr->next;

>     }

> }

>

> void print\_active\_sessions() {

>     session\_t \*curr = session\_list;

>     while (curr) {

>         if (curr->is\_active) {

>             printf("Session %d: %s\\n", curr->session\_id, curr->client\_ip);

>         }

>         curr = curr->next;

>     }

> }

>

> void process\_connection(int id, const char \*ip) {

>     session\_t \*s = create\_session(id, ip);

>     if (!s) {

>         fprintf(stderr, "Failed to create session %d\\n", id);

>         return;

>     }

>

>     /\* Simulate some processing \*/

>     printf("Processing session %d from %s\\n", s->session\_id, s->client\_ip);

>

>     /\* If the IP is from a known internal range, close immediately \*/

>     if (strncmp(ip, "10.", 3) == 0) {

>         close\_session(id);

>         /\* Log the closed session details \*/

>         printf("Auto-closed internal session %d from %s\\n", s->session\_id, s->client\_ip);

>     }

> }

>

> int main() {

>     process\_connection(1, "192.168.1.100");

>     process\_connection(2, "10.0.0.50");

>     process\_connection(3, "172.16.0.1");

>

>     printf("\\nActive sessions:\\n");

>     print\_active\_sessions();

>

>     /\* Cleanup \*/

>     session\_t \*curr = session\_list;

>     while (curr) {

>         session\_t \*next = curr->next;

>         free(curr->client\_ip);

>         free(curr);

>         curr = next;

>     }

>

>     return 0;

> }



\*\*Findings\*\*



1\. \*\*Use-after-free in `process\_connection`\*\*

&#x20;  After `close\_session(id)`, the pointer `s` has been freed. This line dereferences freed memory:



&#x20;  ```c

&#x20;  printf("Auto-closed internal session %d from %s\\n", s->session\_id, s->client\_ip);

&#x20;  ```



&#x20;  This is undefined behavior and could crash, print garbage, or become exploitable. Log the details before calling `close\_session`, or copy the needed values first.



2\. \*\*No check for `strdup` failure\*\*

&#x20;  `create\_session` checks `malloc`, but not `strdup(ip)`. If `strdup` fails, `client\_ip` becomes `NULL`, the half-created session is inserted into the global list, and later `printf("%s", NULL)` or `free` behavior becomes risky.



&#x20;  Fix by checking `s->client\_ip` before linking the session:



&#x20;  ```c

&#x20;  s->client\_ip = strdup(ip);

&#x20;  if (!s->client\_ip) {

&#x20;      free(s);

&#x20;      return NULL;

&#x20;  }

&#x20;  ```



3\. \*\*No validation of `ip`\*\*

&#x20;  If `ip == NULL`, both `strdup(ip)` and `strncmp(ip, "10.", 3)` invoke undefined behavior. Production-facing code should validate inputs.



4\. \*\*Duplicate session IDs are allowed\*\*

&#x20;  `create\_session` blindly prepends a new session even if the same `session\_id` already exists. Then `close\_session(id)` removes only the first match, which may leave stale duplicate sessions active. Either reject duplicates, update the existing session, or define explicit duplicate behavior.



5\. \*\*Global linked list is not thread-safe\*\*

&#x20;  A network monitoring tool may process records concurrently. `session\_list` is shared global state with no locking, so concurrent `create\_session`, `close\_session`, or `print\_active\_sessions` calls can race, corrupt the list, or access freed memory. Use a mutex or confine list access to one thread/event loop.



6\. \*\*`is\_active` is effectively unused\*\*

&#x20;  Sessions are removed from the list when closed, so `is\_active` is never set to `0`. Either remove the field or change close behavior to mark inactive instead of freeing immediately.



7\. \*\*Internal IP check is incomplete\*\*

&#x20;  `strncmp(ip, "10.", 3) == 0` only catches `10.0.0.0/8`. If “known internal range” means RFC1918 private ranges, it misses `172.16.0.0/12` and `192.168.0.0/16`. It also treats strings like `"10.not.an.ip"` as internal. Parse IP addresses properly, for example with `inet\_pton`, then check numeric ranges.



\*\*Most important fix\*\*



Move the log before freeing:



```c

if (strncmp(ip, "10.", 3) == 0) {

&#x20;   printf("Auto-closed internal session %d from %s\\n", s->session\_id, s->client\_ip);

&#x20;   close\_session(id);

}

```



And harden `create\_session` so it does not insert invalid or partially initialized sessions.



