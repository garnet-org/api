package types //nolint:revive // Package name is intentionally descriptive

import (
	"log/slog"

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
	totalSize, err := validateLabelsSize(labels)
	if err != nil {
		slog.Debug("label validation failed",
			"reason", "total_size_exceeded",
			"total_size", totalSize,
			"limit", totalLabelsSizeLimitB,
			"labels", labels,
		)

		return ErrInvalidLabels
	}

	for k, v := range labels {
		if err := validateLabelKey(k); err != nil {
			slog.Debug("label validation failed",
				"reason", "invalid_key",
				"key", k,
				"value", v,
			)

			return err
		}
	}

	return nil
}

func validateLabelsSize(labels map[string]string) (int64, error) {
	var totalSize int64

	for key, value := range labels {
		totalSize += int64(len(key)) + int64(len(value))
	}

	if totalSize > totalLabelsSizeLimitB {
		return totalSize, ErrInvalidLabels
	}

	return totalSize, nil
}

func validateLabelKey(key string) error {
	if len(k8scontentvalidation.IsLabelKey(key)) > 0 {
		return ErrInvalidLabelKey
	}

	return nil
}
