package types //nolint:revive // Package name is intentionally descriptive

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Kubernetes naming convention validation

var (
	// DNS1123LabelFmt matches DNS1123 label format.
	// A DNS-1123 label must consist of lower case alphanumeric characters or '-',
	// and must start and end with an alphanumeric character.
	DNS1123LabelFmt = "[a-z0-9]([-a-z0-9]*[a-z0-9])?"

	// DNS1123SubdomainFmt matches DNS1123 subdomain format.
	// A DNS-1123 subdomain must consist of lower case alphanumeric characters, '-' or '.',
	// and must start and end with an alphanumeric character.
	DNS1123SubdomainFmt = DNS1123LabelFmt + "(\\." + DNS1123LabelFmt + ")*"

	// DNS1123LabelMaxLength is the maximum length of a DNS1123 label.
	DNS1123LabelMaxLength = 63

	// DNS1123SubdomainMaxLength is the maximum length of a DNS1123 subdomain.
	DNS1123SubdomainMaxLength = 253

	// ValidDNS1123LabelRE is a regular expression that validates DNS1123 labels.
	ValidDNS1123LabelRE = regexp.MustCompile("^" + DNS1123LabelFmt + "$")

	// ValidDNS1123SubdomainRE is a regular expression that validates DNS1123 subdomains.
	ValidDNS1123SubdomainRE = regexp.MustCompile("^" + DNS1123SubdomainFmt + "$")
)

// ValidateK8sClusterName validates a Kubernetes cluster name.
// Kubernetes cluster names should adhere to DNS1123 subdomain format.
func ValidateK8sClusterName(name string) error {
	if name == "" {
		return errors.New("cluster name cannot be empty")
	}

	if len(name) > DNS1123SubdomainMaxLength {
		return fmt.Errorf("cluster name '%s' must be no more than %d characters", name, DNS1123SubdomainMaxLength)
	}

	if !ValidDNS1123SubdomainRE.MatchString(name) {
		// Generate a more helpful error message
		return fmt.Errorf("cluster name '%s' must consist of lower case alphanumeric characters, '-' or '.', "+
			"and must start and end with an alphanumeric character", name)
	}

	return nil
}

// ValidateK8sNodeName validates a Kubernetes node name.
// Node names should follow DNS1123 subdomain format, but may also include upper case letters.
func ValidateK8sNodeName(name string) error {
	if name == "" {
		return errors.New("node name cannot be empty")
	}

	if len(name) > DNS1123SubdomainMaxLength {
		return fmt.Errorf("node name '%s' must be no more than %d characters", name, DNS1123SubdomainMaxLength)
	}

	// Convert to lowercase for checking DNS1123 format, but allow uppercase in the actual node name
	lowercaseName := strings.ToLower(name)
	if !ValidDNS1123SubdomainRE.MatchString(lowercaseName) {
		return fmt.Errorf("node name '%s' must consist of alphanumeric characters, '-' or '.', "+
			"and must start and end with an alphanumeric character", name)
	}

	return nil
}

// ValidateK8sNamespace validates a Kubernetes namespace name.
// Namespace names should follow DNS1123 label format.
func ValidateK8sNamespace(name string) error {
	// Namespaces can be empty (for default namespace)
	if name == "" {
		return nil
	}

	if len(name) > DNS1123LabelMaxLength {
		return fmt.Errorf("namespace '%s' must be no more than %d characters", name, DNS1123LabelMaxLength)
	}

	if !ValidDNS1123LabelRE.MatchString(name) {
		return fmt.Errorf("namespace '%s' must consist of lower case alphanumeric characters or '-', "+
			"and must start and end with an alphanumeric character", name)
	}

	return nil
}