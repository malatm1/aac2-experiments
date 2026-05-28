\# trial-reviewer-01



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



&#x20;  After this block:



&#x20;  ```c

&#x20;  close\_session(id);

&#x20;  printf("Auto-closed internal session %d from %s\\n", s->session\_id, s->client\_ip);

&#x20;  ```



&#x20;  `close\_session` frees the `session\_t` and `client\_ip`. The pointer `s` is now dangling, so reading `s->session\_id` or `s->client\_ip` is undefined behavior. This can crash, print garbage, or become exploitable.



&#x20;  Fix by logging before freeing, or copy the values before calling `close\_session`:



&#x20;  ```c

&#x20;  printf("Auto-closed internal session %d from %s\\n", s->session\_id, s->client\_ip);

&#x20;  close\_session(id);

&#x20;  ```



2\. \*\*`strdup(ip)` result is not checked\*\*



&#x20;  In `create\_session`:



&#x20;  ```c

&#x20;  s->client\_ip = strdup(ip);

&#x20;  ```



&#x20;  If allocation fails, `client\_ip` becomes `NULL`, but the session is still inserted into the list. Later `printf("%s", s->client\_ip)` has undefined behavior on many platforms.



&#x20;  Fix:



&#x20;  ```c

&#x20;  s->client\_ip = strdup(ip);

&#x20;  if (!s->client\_ip) {

&#x20;      free(s);

&#x20;      return NULL;

&#x20;  }

&#x20;  ```



3\. \*\*No validation for `ip == NULL`\*\*



&#x20;  `strdup(ip)`, `strncmp(ip, "10.", 3)`, and `printf("%s", ip)` all assume `ip` is non-null. If malformed input reaches this function, it can crash.



&#x20;  Fix by rejecting null input early:



&#x20;  ```c

&#x20;  if (!ip) return NULL;

&#x20;  ```



&#x20;  or return an error from `process\_connection`.



4\. \*\*Duplicate session IDs are allowed\*\*



&#x20;  `create\_session` always prepends a new session without checking whether `id` already exists. Then `close\_session(id)` closes only the first matching node. In a monitoring tool, duplicate IDs could leave stale sessions active or close the wrong record.



&#x20;  Fix by enforcing unique IDs, replacing existing sessions intentionally, or making the session key include more fields.



5\. \*\*Global `session\_list` is unsafe for concurrent use\*\*



&#x20;  Network monitoring tools often process records from multiple threads or callbacks. This linked list has no locking, so concurrent `create\_session`, `close\_session`, `print\_active\_sessions`, or cleanup can race and corrupt memory.



&#x20;  Fix with a mutex around all list access, or move ownership into a single-threaded event loop.



6\. \*\*Internal IP detection is incomplete and string-based\*\*



&#x20;  This only catches addresses beginning with `"10."`:



&#x20;  ```c

&#x20;  strncmp(ip, "10.", 3) == 0

&#x20;  ```



&#x20;  It misses other private ranges like `172.16.0.0/12` and `192.168.0.0/16`, and it trusts textual formatting. For production, parse the IP address with `inet\_pton` and compare numeric ranges.



\*\*Most important fix\*\*



The use-after-free is the production blocker. Move the auto-close log before `close\_session`, or preserve the data before freeing. Also add allocation/null checks around `strdup` before this code ships.



