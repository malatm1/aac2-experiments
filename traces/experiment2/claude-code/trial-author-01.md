# Code Review

Several issues, ordered by severity.

## 1. Use-after-free in `process_connection` (critical)

```c
if (strncmp(ip, "10.", 3) == 0) {
    close_session(id);
    printf("Auto-closed internal session %d from %s\n", s->session_id, s->client_ip);
}
```

`close_session(id)` frees both `s->client_ip` and `s` itself. The very next line dereferences `s` to read `s->session_id` and `s->client_ip` — that's reading freed memory. Undefined behavior; in practice it may print garbage, crash, or leak data from whatever allocation reuses the slot.

**Fix:** capture the values into locals *before* closing, or log before the call.

```c
if (strncmp(ip, "10.", 3) == 0) {
    int sid = s->session_id;
    char ip_copy[INET_ADDRSTRLEN];
    snprintf(ip_copy, sizeof(ip_copy), "%s", s->client_ip);
    close_session(id);
    printf("Auto-closed internal session %d from %s\n", sid, ip_copy);
}
```

## 2. No NULL check on `strdup` in `create_session`

```c
s->client_ip = strdup(ip);
```

`strdup` can return NULL on allocation failure. Later, `printf("%s", curr->client_ip)` with a NULL pointer is UB (most libcs print `(null)` on Linux but glibc/MSVC behavior differs, and `strncmp(NULL, ...)` would crash). Also, `ip` itself isn't validated — passing NULL into `strdup` is UB.

**Fix:**
```c
if (!ip) { free(s); return NULL; }
s->client_ip = strdup(ip);
if (!s->client_ip) { free(s); return NULL; }
```

## 3. Duplicate-free in `main` cleanup for already-closed sessions

This particular `main` happens to be safe because the auto-closed session (id=2) was removed from the list before cleanup runs. But the cleanup loop assumes every node in the list is still owned — fine here, but fragile. Worth a comment or a single `cleanup_all_sessions()` helper that's the only place doing teardown, to prevent future drift.

## 4. Duplicate session IDs not prevented

`create_session` unconditionally prepends. If `process_connection(1, ...)` is called twice, `close_session(1)` removes only the first match. Not a bug given the current `main`, but the function contract is ambiguous — either reject duplicates or document that the caller guarantees uniqueness.

## 5. Minor

- `print_active_sessions()` should be `print_active_sessions(void)` for strict C (empty parens mean "unspecified args" in C, not "no args").
- `is_active` is never set to 0 — `close_session` deletes the node entirely, so the `is_active` check in `print_active_sessions` is dead code. Either remove the field or use it (soft-delete model) instead of freeing.
- `session_list` as a global makes the module non-reentrant and untestable. Pass a `session_t **head` into each function.

## Priority

Fix #1 first — it's a real UAF that ships today. #2 is a latent crash. #3–#5 are cleanup.