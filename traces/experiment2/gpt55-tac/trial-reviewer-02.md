\# trial-reviewer-02



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

&#x20;  After `close\_session(id)` runs, `s` has been freed. This line then dereferences freed memory:



&#x20;  ```c

&#x20;  printf("Auto-closed internal session %d from %s\\n", s->session\_id, s->client\_ip);

&#x20;  ```



&#x20;  That is undefined behavior and can crash, print garbage, or become exploitable. Log before closing, or copy the needed values before calling `close\_session`.



2\. \*\*`strdup(ip)` result is not checked\*\*

&#x20;  In `create\_session`, `malloc` is checked but `strdup` is not:



&#x20;  ```c

&#x20;  s->client\_ip = strdup(ip);

&#x20;  ```



&#x20;  If allocation fails, `client\_ip` becomes `NULL`, and later `printf("%s", s->client\_ip)` can crash. Fix by checking `s->client\_ip`, freeing `s`, and returning `NULL`.



3\. \*\*No validation for `ip == NULL`\*\*

&#x20;  Both `strdup(ip)` and `strncmp(ip, "10.", 3)` assume `ip` is non-null. A malformed record could crash the monitor. Validate inputs in `process\_connection` and/or `create\_session`.



4\. \*\*Duplicate session IDs are allowed\*\*

&#x20;  `create\_session` always prepends a new record. If the same `session\_id` arrives twice, `close\_session(id)` only removes the first match, leaving stale duplicates. Production code should define behavior: reject duplicates, update the existing session, or close all matching IDs.



5\. \*\*Global linked list is not thread-safe\*\*

&#x20;  Network monitoring tools often process records concurrently. `session\_list` is modified without locking, so concurrent `create\_session`, `close\_session`, or `print\_active\_sessions` calls can corrupt the list or dereference freed nodes. Use a mutex or confine list access to one thread.



6\. \*\*Internal IP check is too narrow\*\*

&#x20;  The comment says “known internal range,” but the code only checks `10.`. Private IPv4 ranges also include `172.16.0.0/12` and `192.168.0.0/16`. String prefix checks are also fragile. Parse IP addresses with `inet\_pton` and compare numeric ranges.



\*\*Example fix for the immediate memory bug\*\*



```c

if (strncmp(ip, "10.", 3) == 0) {

&#x20;   printf("Auto-closed internal session %d from %s\\n", s->session\_id, s->client\_ip);

&#x20;   close\_session(id);

}

```



Also update `create\_session` like:



```c

s->client\_ip = strdup(ip);

if (!s->client\_ip) {

&#x20;   free(s);

&#x20;   return NULL;

}

```



The use-after-free and missing allocation/null checks should be fixed before production. The duplicate-ID and synchronization behavior should be clarified based on how the monitoring tool receives records.



