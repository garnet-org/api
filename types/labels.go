package types //nolint:revive // Package name is intentionally descriptive

import (
	"github.com/garnet-org/api/types/errs"
	k8scontentvalidation "k8s.io/apimachinery/pkg/api/validate/content"
	k8sapivalidation "k8s.io/apimachinery/pkg/api/validation"
)

const totalLabelsSizeLimitB = int64(k8sapivalidation.TotalAnnotationSizeLimitB)

// Label error constants.
var (
	ErrInvalidLabels   = errs.InvalidArgumentError("invalid labels")
	ErrInvalidLabelKey = errs.InvalidArgumentError("invalid label key")
)

// ValidateLabels validates a map of labels against the defined constraints.
func ValidateLabels(labels map[string]string) error {

	if err := validateLabelsSize(labels); err != nil {
		return ErrInvalidLabels
	}

	for k := range labels {
		if err := validateLabelKey(k); err != nil {
			return err
		}
	}

	return nil
}

func validateLabelsSize(labels map[string]string) error {
	var totalSize int64

	for key, value := range labels {
		totalSize += int64(len(key)) + int64(len(value))
	}

	if totalSize > totalLabelsSizeLimitB {
		return ErrInvalidLabels
	}

	return nil
}

func validateLabelKey(key string) error {
	if len(k8scontentvalidation.IsLabelKey(key)) > 0 {
		return ErrInvalidLabelKey
	}

	return nil
}
