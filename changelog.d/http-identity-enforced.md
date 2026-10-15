### Security: the job's identification reaches every request, or the task is refused

- The tool host now enforces the organization's identification (`http_policy` User-Agent and headers, such as a bug-bounty program's required header) per task. Before, `Context.HTTP` only added it when the tool set no value of its own, and an exec tool received the headers nowhere: a program's targets could be probed without its required identification.
- `Task.Identity` carries it. `Context.HTTP` sets it on every request, redirects included, over what the tool set.
- An exec tool receives it through `{{http.user_agent}}` and the new `{{http.headers:-flag}}` (the flag and `Name: value` per header).
- A tool that may send HTTP to its targets and can do neither is refused (`refused_by_policy`). Port scans, host discovery and DNS lookups, and tools that reach no target, are not affected. A tool that applies it itself declares `features.http_identity` (new descriptor key).

### Upgrade notes

- Tools that receive identification-carrying jobs must pass `{{http.user_agent}}` and `{{http.headers:-flag}}` on their argv or declare `features.http_identity`; otherwise those tasks are refused.
