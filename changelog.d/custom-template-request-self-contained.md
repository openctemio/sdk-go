### Security: custom template check covers request-level self-contained and include directives

- `core.CheckCustomTemplate` now refuses a nuclei template whose request (not only the template) sets `self-contained` to anything but false, at any depth: such a request is sent to the URL in the template instead of the scan's target.
- It also refuses nuclei's `# !include:` preprocessor directive, which inlines a file from the sensor's disk that the check never reads.
