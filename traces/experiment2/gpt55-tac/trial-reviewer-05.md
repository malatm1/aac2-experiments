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



1\. \*\*Use-after-free in `process\_connection` after `close\_session(id)`\*\*

&#x20;  After `close\_session(id)` frees the matching `session\_t`, `process\_connection` still reads `s->session\_id` and `s->client\_ip`:



&#x20;  ```c

&#x20;  close\_session(id);

&#x20;  printf("Auto-closed internal session %d from %s\\n", s->session\_id, s->client\_ip);

&#x20;  ```



&#x20;  This is undefined behavior and could crash or leak stale memory contents. Log before freeing, or copy the needed fields before calling `close\_session`.



2\. \*\*`strdup(ip)` failure is not handled\*\*

&#x20;  `create\_session` checks `malloc`, but not `strdup`. If `strdup` fails, `client\_ip` becomes `NULL`, the session is still inserted into the list, and later `printf("%s", curr->client\_ip)` may crash.



&#x20;  Fix:



&#x20;  ```c

&#x20;  s->client\_ip = strdup(ip);

&#x20;  if (!s->client\_ip) {

&#x20;      free(s);

&#x20;      return NULL;

&#x20;  }

&#x20;  ```



3\. \*\*No validation for `ip == NULL`\*\*

&#x20;  `strdup(ip)` and `strncmp(ip, "10.", 3)` both dereference `ip`. If malformed input reaches this function, the program can crash. Production network-monitoring code should reject or sanitize null/invalid IP strings.



4\. \*\*Duplicate session IDs are allowed\*\*

&#x20;  `create\_session` always inserts a new session. If the same `id` appears twice, `close\_session(id)` removes only the first match, leaving duplicates behind. That can corrupt session accounting or close the wrong logical session. Enforce unique IDs, update existing sessions, or define duplicate behavior explicitly.



5\. \*\*Global linked list is not thread-safe\*\*

&#x20;  A network monitoring tool may process records concurrently. `session\_list` is mutated without locking, so concurrent calls to `create\_session`, `close\_session`, or `print\_active\_sessions` could race, corrupt the list, or read freed memory. Use a mutex or confine all access to one event loop/thread.



6\. \*\*`is\_active` is misleading\*\*

&#x20;  Sessions are removed from the list when closed, so `is\_active` is never set to `0` and has no real effect. Either remove the field or implement a real inactive state. As written, it creates a false impression that closed sessions might remain tracked.



7\. \*\*Internal IP detection is incomplete\*\*

&#x20;  The comment says “known internal range,” but the code only detects `10.\*`. Private IPv4 ranges also include `172.16.0.0/12` and `192.168.0.0/16`. String prefix checks are also fragile; parse IP addresses numerically and check CIDR ranges.



\*\*Most urgent fix\*\*



Move the auto-close log before freeing, or copy values first:



```c

if (strncmp(ip, "10.", 3) == 0) {

&#x20;   printf("Auto-closed internal session %d from %s\\n", s->session\_id, s->client\_ip);

&#x20;   close\_session(id);

}

```



Also add `strdup` failure handling before this goes anywhere near production.



