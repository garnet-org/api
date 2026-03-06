package types //nolint:revive // Package name is intentionally descriptive

import (
	"bytes"
	"encoding/json"

	"github.com/garnet-org/jibril-ashkaal/pkg/ongoing"
)

// UnmarshalOngoingBaseCompat unmarshals JSON for ongoing.Base, sanitizing obviously-invalid
// legacy values (e.g. time fields set to the string "running" or non-RFC3339 timestamps)
// before decoding.
func UnmarshalOngoingBaseCompat(data []byte, out *ongoing.Base) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		*out = ongoing.Base{}
		return nil
	}

	raw := json.RawMessage(data)
	if normalized, ok := normalizeAshkaalBaseJSON(raw); ok {
		raw = normalized
	}

	return json.Unmarshal(raw, out)
}
