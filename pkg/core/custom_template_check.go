package core

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// The sensor's own check of an organization's custom templates, before
// anything is written for a scanner. The platform refuses the same at
// upload and signs only what it accepted; this check runs on the sensor
// so that a template that slipped past the platform (or a platform key in
// the wrong hands) still cannot run code here. Because every custom
// template passes it, a scanner may load custom templates together with
// its own in one run (RuleSourcesBoth) without a separate restricted run.

// nucleiForbiddenKeys are the top-level template keys a custom nuclei
// template may not have: blocks that run code on the sensor (code,
// javascript, and flow, which is JavaScript run by the engine's embedded
// interpreter), read its disk (file) or drive a browser (headless).
// Compared case-insensitively: the engine also reads JSON templates, whose
// keys match any case. No setting enables them.
var nucleiForbiddenKeys = []string{"code", "javascript", "flow", "file", "headless"}

// nucleiIncludeDirective is nuclei's include preprocessor directive
// ("# !include:<file>.yaml"): a comment to a YAML parser, but nuclei
// inlines the named file from the sensor's disk before it parses the
// template, so this check would never see what runs.
var nucleiIncludeDirective = regexp.MustCompile(`(?i)#\s*!include:`)

// CheckCustomTemplate checks one custom template's content for its type:
// a nuclei template must be a single YAML document without a forbidden
// block (nucleiForbiddenKeys), an include directive
// (nucleiIncludeDirective), self-contained requests (the template's or
// any one request's), workflows (they
// resolve other templates from the sensor's disk, outside the signed set)
// or payload lists loaded from files. Other types are not inspected here
// (their scanners run no code from rules).
func CheckCustomTemplate(templateType string, raw []byte) error {
	if !strings.EqualFold(strings.TrimSpace(templateType), "nuclei") {
		return nil
	}
	return CheckNucleiCustomTemplate(raw)
}

// CheckNucleiCustomTemplate is CheckCustomTemplate for a nuclei template.
func CheckNucleiCustomTemplate(raw []byte) error {
	if nucleiIncludeDirective.Match(raw) {
		return errors.New("custom templates may not include files from the sensor's disk (# !include)")
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("not a YAML template: %w", err)
	}
	// One document only: a second one is content this check would not read
	// but a parser might.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("a template must be one YAML document")
	}
	for key := range doc {
		k := strings.TrimSpace(key)
		for _, bad := range nucleiForbiddenKeys {
			if strings.EqualFold(k, bad) {
				return fmt.Errorf("the %s block is never run for custom templates", bad)
			}
		}
		if strings.EqualFold(k, "workflows") {
			return errors.New("custom templates may not run other templates (workflows)")
		}
	}
	// self-contained is a template key and also a key of each request
	// (an http request's own "self-contained: true" sends it to the URL in
	// the template instead of the scan's target): refused at any depth.
	if selfContained(doc, 0) {
		return errors.New("self-contained templates are never run for custom templates")
	}
	if ref, ok := nucleiPayloadFile(doc); ok {
		return fmt.Errorf("custom templates may not load payload files from the sensor's disk (%q)", ref)
	}
	return nil
}

// maxTemplateDepth bounds the walk of a template's tree (selfContained);
// a template nested deeper is refused.
const maxTemplateDepth = 64

// selfContained reports whether v has a "self-contained" key (any case) at
// any depth whose value is not false, or nests deeper than
// maxTemplateDepth.
func selfContained(v any, depth int) bool {
	if depth > maxTemplateDepth {
		return true
	}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if strings.EqualFold(strings.TrimSpace(k), "self-contained") {
				if b, ok := val.(bool); !ok || b {
					return true
				}
			}
			if selfContained(val, depth+1) {
				return true
			}
		}
	case []any:
		for _, val := range t {
			if selfContained(val, depth+1) {
				return true
			}
		}
	}
	return false
}

// nucleiPayloadFile finds a payload list loaded from a file (a string value
// under any request block's payloads): a custom template carries its
// payloads inline, so a path names a file on the sensor.
func nucleiPayloadFile(doc map[string]any) (string, bool) {
	for _, v := range doc {
		blocks, _ := v.([]any)
		for _, b := range blocks {
			block, _ := b.(map[string]any)
			for k, p := range block {
				if !strings.EqualFold(strings.TrimSpace(k), "payloads") {
					continue
				}
				m, _ := p.(map[string]any)
				for _, val := range m {
					if s, ok := val.(string); ok {
						return s, true
					}
				}
			}
		}
	}
	return "", false
}
