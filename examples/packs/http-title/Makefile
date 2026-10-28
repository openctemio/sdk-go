.PHONY: validate test conformance

validate:
	openctem tool validate .

# Self-tests and the protocol checks.
test: validate
	openctem tool test .

# The full kit: the capability suites on local fixtures, the scope check and
# parser fuzzing. The stub finds nothing, so it fails until the tool is real.
conformance: validate
	openctem tool test --capability --scope --fuzz 30s .
