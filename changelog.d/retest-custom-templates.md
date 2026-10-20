### Added: retests can run a check the platform delivers

- A retest command may carry custom templates (`custom_templates`, optionally `custom_templates_envelope`) and items that name one (`"template": "<id>"`). `Kit.HandleRetestTemplates(name, run)` serves such retests for a tool and reports capability `retest-templates:<tool>` (`toolcompat.RetestTemplatesCapability`) beside `retest:<tool>`; sensors that do not opt in are unchanged and never receive such a command.
- `tool.RetestItem.TemplatePath`: the file of the delivered check for that item, set by the sensor only. The tool runs exactly that file and reports its digest; a templated `fixed` or `still_present` verdict under another digest becomes `unverifiable`.

### Security: one template check for every command type

- Delivered retest templates pass exactly the scan path's checks before anything is written: the local policy's `allow_custom_templates`, the signed job's template digests (else the per-tenant template manifest bound to this sensor and command) and `core.CheckCustomTemplate`. An item naming a template the command does not carry, a template of another tool's type, or a tool that did not opt in fails the command.
- `core.DefaultCommandExecutor.VerifyCustomTemplates` and `core.CommandTemplates` expose that check; `core.WriteCustomTemplates` writes verified templates to a private temporary directory (0700, files 0600) and returns each file and the cleanup.
