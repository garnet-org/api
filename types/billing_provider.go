package types

import (
	"encoding/json"
	"time"

	"github.com/garnet-org/api/types/errs"
)

var ErrInvalidPolarWebhookSignature = errs.UnauthorizedError("invalid polar webhook signature")

type BillingCheckout struct {
	ProductID          string                  `json:"productID"`
	ExternalCustomerID string                  `json:"externalCustomerID"`
	CustomerName       *string                 `json:"customerName"`
	CustomerEmail      *string                 `json:"customerEmail"`
	SuccessURL         string                  `json:"successURL"`
	ReturnURL          *string                 `json:"returnURL"`
	Locale             *string                 `json:"locale"`
	Metadata           BillingCheckoutMetadata `json:"metadata"`
}

type BillingCheckoutMetadata struct {
	ProjectID            string `json:"projectID"`
	InitiatedByUserID    string `json:"initiatedByUserID"`
	BillingMetricVersion int64  `json:"billingMetricVersion"`
}

type BillingCustomerPortal struct {
	ExternalCustomerID string  `json:"externalCustomerID"`
	ReturnURL          *string `json:"returnURL"`
}

type BillingUsageEvent struct {
	EventName          string                    `json:"eventName"`
	ExternalCustomerID string                    `json:"externalCustomerID"`
	ExternalEventID    string                    `json:"externalEventID"`
	OccurredAt         time.Time                 `json:"occurredAt"`
	Metadata           BillingUsageEventMetadata `json:"metadata"`
}

type BillingUsageEventMetadata struct {
	ProjectID        string `json:"projectID"`
	MetricKey        string `json:"metricKey"`
	SourceEntityKind string `json:"sourceEntityKind"`
	SourceEntityID   string `json:"sourceEntityID"`
	Quantity         int64  `json:"quantity"`
}

type VerifiedPolarWebhook struct {
	PolarEventID   string          `json:"polarEventID"`
	PolarEventKind string          `json:"polarEventKind"`
	PolarPayload   json.RawMessage `json:"polarPayload"`
}

type CreatePolarWebhookEvent struct {
	PolarEventID   string
	PolarEventKind string
	PolarPayload   json.RawMessage
}

type CreateBillingUsageOutboxItem struct {
	ProjectID        string
	MetricKey        string
	SourceEntityKind string
	SourceEntityID   string
	Quantity         int64
	OccurredAt       time.Time
	Payload          any
}
