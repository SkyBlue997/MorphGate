package intelsync

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"

	"go.yaml.in/yaml/v3"
)

const maxSourceFileSize = 1 << 20

// RegistrySource is the owner-maintained crawler registry source
// (`deploy/intel/crawler-registry.yaml`, docs/impl/phase1-spec.md §12.3).
type RegistrySource struct {
	Version int `yaml:"version"`
	// Test marks a registry for the Validation Lab and tests only: the
	// documentation ranges become valid and the artifact carries
	// "test": true, which the Edge logs as a warning.
	Test      bool             `yaml:"test"`
	Operators []SourceOperator `yaml:"operators"`
}

// SourceOperator is one operator in the source file.
type SourceOperator struct {
	ID       string       `yaml:"id"`
	Name     string       `yaml:"name"`
	Purpose  string       `yaml:"purpose"`
	UATokens []string     `yaml:"ua_tokens"`
	Verify   SourceVerify `yaml:"verify"`
}

// SourceVerify is the verification method and where to fetch official ranges.
type SourceVerify struct {
	Mode         string          `yaml:"mode"`
	RDNSSuffixes []string        `yaml:"rdns_suffixes"`
	IPRanges     []SourceIPRange `yaml:"ip_ranges"`
}

// SourceIPRange is one official range list.
type SourceIPRange struct {
	URL    string `yaml:"url"`
	Format string `yaml:"format"`
}

// ParseRegistrySource parses and validates the source YAML. Unknown keys,
// anchors / aliases and multiple documents are errors, as for site and policy
// files.
func ParseRegistrySource(file string, data []byte) (*RegistrySource, error) {
	if len(data) > maxSourceFileSize {
		return nil, fmt.Errorf("%s: larger than %d bytes", file, maxSourceFileSize)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: empty file", file)
		}
		return nil, fmt.Errorf("%s: invalid YAML: %w", file, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("%s:%d: multiple YAML documents are not supported", file, extra.Line)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: invalid YAML: %w", file, err)
	}
	if n := findAlias(&doc); n != nil {
		return nil, fmt.Errorf("%s:%d: YAML anchors, aliases and merge keys are not supported", file, n.Line)
	}
	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	var src RegistrySource
	if err := strict.Decode(&src); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if err := src.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return &src, nil
}

func findAlias(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.AliasNode || n.Anchor != "" || (n.Kind == yaml.ScalarNode && n.Tag == "!!merge") {
		return n
	}
	for _, c := range n.Content {
		if a := findAlias(c); a != nil {
			return a
		}
	}
	return nil
}

// Validate checks the source against §12.3.
func (s *RegistrySource) Validate() error {
	if s.Version != 1 {
		return fmt.Errorf("version must be 1, got %d", s.Version)
	}
	if len(s.Operators) == 0 || len(s.Operators) > maxOperators {
		return fmt.Errorf("%d operators, want 1-%d", len(s.Operators), maxOperators)
	}
	seen := map[string]bool{}
	for i, op := range s.Operators {
		if err := validateOperatorMeta(op.ID, op.Name, op.Purpose, op.UATokens, op.Verify.Mode, op.Verify.RDNSSuffixes); err != nil {
			return fmt.Errorf("operator %d: %w", i, err)
		}
		if seen[op.ID] {
			return fmt.Errorf("duplicate operator id %q", op.ID)
		}
		seen[op.ID] = true
		if op.Verify.Mode == ModeIPRanges && len(op.Verify.IPRanges) == 0 {
			return fmt.Errorf("operator %q: verify.mode ip_ranges needs verify.ip_ranges", op.ID)
		}
		if len(op.Verify.IPRanges) > maxSourcesPerOperator {
			return fmt.Errorf("operator %q: %d ip_ranges, at most %d", op.ID, len(op.Verify.IPRanges), maxSourcesPerOperator)
		}
		var urls []string
		for _, r := range op.Verify.IPRanges {
			if _, err := checkHTTPSURL(r.URL); err != nil {
				return fmt.Errorf("operator %q: %w", op.ID, err)
			}
			if !slices.Contains(formats, r.Format) {
				return fmt.Errorf("operator %q: format %q must be one of %v", op.ID, r.Format, formats)
			}
			if slices.Contains(urls, r.URL) {
				return fmt.Errorf("operator %q: duplicate ip_ranges url %s", op.ID, r.URL)
			}
			urls = append(urls, r.URL)
		}
	}
	return nil
}
