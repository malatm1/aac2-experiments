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



&#x20;  This is undefined behavior and production-critical. It may print garbage, crash, or become exploitable. Log before freeing, or copy the needed values before calling `close\_session`.



2\. \*\*`strdup(ip)` failure is not handled\*\*

&#x20;  `create\_session` checks `malloc`, but not `strdup`. If `strdup` fails, `client\_ip` becomes `NULL`, yet the partially created session is inserted into the list. Later `printf("%s", s->client\_ip)` can crash.



&#x20;  Fix by checking `s->client\_ip` before linking the session:



&#x20;  ```c

&#x20;  s->client\_ip = strdup(ip);

&#x20;  if (!s->client\_ip) {

&#x20;      free(s);

&#x20;      return NULL;

&#x20;  }

&#x20;  ```



3\. \*\*`ip == NULL` is not handled\*\*

&#x20;  `strdup(ip)` and `strncmp(ip, "10.", 3)` both crash if `ip` is `NULL`. Since this is processing incoming network records, inputs should be treated as untrusted. Validate `ip` at the API boundary.



4\. \*\*Duplicate session IDs are allowed\*\*

&#x20;  `create\_session` always prepends a new session. If two records use the same `session\_id`, `close\_session(id)` removes only the first match. This can leave stale duplicate sessions behind and make logging/cleanup behavior ambiguous.



&#x20;  Decide whether session IDs must be unique. If yes, reject duplicates or update the existing session.



5\. \*\*`is\_active` is redundant or misleading\*\*

&#x20;  Sessions are physically removed from the list when closed, so `is\_active` is always `1` for listed sessions. Either remove the field or change `close\_session` to mark inactive instead of freeing immediately. Keeping both models invites future bugs.



6\. \*\*Global `session\_list` is not thread-safe\*\*

&#x20;  A network monitoring tool may process records concurrently. `create\_session`, `close\_session`, cleanup, and `print\_active\_sessions` all mutate or traverse shared global state without locking. In production, this needs synchronization or ownership confined to a single event loop.



7\. \*\*IP range check is too naive\*\*

&#x20;  `strncmp(ip, "10.", 3)` only checks a string prefix. It does not validate that the IP is syntactically valid, and it ignores other private ranges like `172.16.0.0/12` and `192.168.0.0/16` if those are meant to be internal. Parse addresses with `inet\_pton` and compare numeric ranges.



\*\*Minimum fix for the immediate memory bug\*\*



```c

if (strncmp(ip, "10.", 3) == 0) {

&#x20;   printf("Auto-closed internal session %d from %s\\n", s->session\_id, s->client\_ip);

&#x20;   close\_session(id);

}

```



Also fix `strdup` failure handling before this goes anywhere near production. The use-after-free and unchecked allocation are the two biggest blockers.



