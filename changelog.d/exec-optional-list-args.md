### Added: exec tools take list, optional and switch settings in run.argv

- Besides `{{config.k}}`, an exec tool's `run.argv` may use:
  - `{{config.k?}}`: the argument is left out when the key is not set, empty or false;
  - `{{config.k...}}`: an array key, one argument per item, or comma-joined inside a larger argument; left out when empty;
  - `{{config.k?:-flag}}`: a boolean key, the flag only when true.

  Before, a list param (`record_types`, `tags`) could not reach a CLI at all, and an unset key became an empty argument. Every value keeps the flag-injection and dangerous-flag checks.
- `openctem tool validate` (and the kit's lint) warns when an exec tool maps a capability param onto a config key that no argument uses: the tool would accept the param and ignore it.
- `tool.ConfigArg` and `tool.ArgvPlaceholders` parse the placeholders.
