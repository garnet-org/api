package types

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/garnet-org/api/types/errs"
	"github.com/garnet-org/api/validator"
)

const (
	BillingMetricKeyProfileCreated = "profile_created"
	PolarBillingProvider           = "polar"
)

type BillingPlan string

const (
	BillingPlanFree     BillingPlan = "free"
	BillingPlanBypassed BillingPlan = "bypassed"
	BillingPlanPaid     BillingPlan = "paid"
)

const (
	ErrBillingAccountNotFound     = errs.NotFoundError("billing account not found")
	ErrProfileLimitExceeded       = errs.PermissionDeniedError("profile limit exceeded for current billing period")
	ErrBillingCustomerUnavailable = errs.ConflictError("billing customer is not available for this project")
	ErrBillingPlanBypassed        = errs.ConflictError("billing is bypassed for this project")
)

const billingBypassEmailDomain = "garnet.ai"

func BillingPlanForEmail(email string) BillingPlan {
	if BillingPlanIsBypassedForEmail(email) {
		return BillingPlanBypassed
	}

	return BillingPlanFree
}

func BillingPlanIsBypassedForEmail(email string) bool {
	email = strings.TrimSpace(strings.ToLower(email))
	_, domain, found := strings.Cut(email, "@")
	if !found {
		return false
	}

	return domain == billingBypassEmailDomain
}

func BillingPlanEnforcesLimit(plan BillingPlan) bool {
	return plan == BillingPlanFree
}

type BillingMetric struct {
	Key                    string    `json:"key" db:"key"`
	DisplayName            string    `json:"displayName" db:"display_name"`
	Aggregation            string    `json:"aggregation" db:"aggregation"`
	Provider               string    `json:"provider" db:"provider"`
	PolarEventName         string    `json:"polarEventName" db:"polar_event_name"`
	IncludedQuantity       int64     `json:"includedQuantity" db:"included_quantity"`
	OverageUnitAmountCents int64     `json:"overageUnitAmountCents" db:"overage_unit_amount_cents"`
	Currency               string    `json:"currency" db:"currency"`
	CreatedAt              time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt              time.Time `json:"updatedAt" db:"updated_at"`
}

type BillingAccount struct {
	ProjectID           string          `json:"projectID" db:"project_id"`
	Provider            string          `json:"provider" db:"provider"`
	Plan                BillingPlan     `json:"plan" db:"plan"`
	PolarStatus         *string         `json:"polarStatus" db:"polar_status"`
	ExternalCustomerID  string          `json:"externalCustomerID" db:"external_customer_id"`
	PolarCustomerID     *string         `json:"polarCustomerID" db:"polar_customer_id"`
	PolarSubscriptionID *string         `json:"polarSubscriptionID" db:"polar_subscription_id"`
	PolarProductID      *string         `json:"polarProductID" db:"polar_product_id"`
	CurrentPeriodStart  time.Time       `json:"currentPeriodStart" db:"current_period_start"`
	CurrentPeriodEnd    time.Time       `json:"currentPeriodEnd" db:"current_period_end"`
	CancelAtPeriodEnd   bool            `json:"cancelAtPeriodEnd" db:"cancel_at_period_end"`
	CanceledAt          *time.Time      `json:"canceledAt" db:"canceled_at"`
	LastPolarEventID    *string         `json:"lastPolarEventID" db:"polar_last_event_id"`
	LastPolarEventKind  *string         `json:"lastPolarEventKind" db:"polar_last_event_kind"`
	LastPolarEventAt    *time.Time      `json:"lastPolarEventAt" db:"polar_last_event_at"`
	RawPolarPayload     json.RawMessage `json:"-" db:"polar_payload"`
	CreatedAt           time.Time       `json:"createdAt" db:"created_at"`
	UpdatedAt           time.Time       `json:"updatedAt" db:"updated_at"`
}

type BillingUsagePeriod struct {
	ProjectID        string    `json:"projectID" db:"project_id"`
	MetricKey        string    `json:"metricKey" db:"metric_key"`
	PeriodStart      time.Time `json:"periodStart" db:"period_start"`
	PeriodEnd        time.Time `json:"periodEnd" db:"period_end"`
	IncludedQuantity int64     `json:"includedQuantity" db:"included_quantity"`
	Quantity         int64     `json:"quantity" db:"quantity"`
	CreatedAt        time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt        time.Time `json:"updatedAt" db:"updated_at"`
}

type BillingMetricDetails struct {
	Key                    string `json:"key" db:"key"`
	DisplayName            string `json:"displayName" db:"display_name"`
	Aggregation            string `json:"aggregation" db:"aggregation"`
	IncludedQuantity       int64  `json:"includedQuantity" db:"included_quantity"`
	UsedQuantity           int64  `json:"usedQuantity" db:"used_quantity"`
	RemainingQuantity      int64  `json:"remainingQuantity" db:"remaining_quantity"`
	OverageUnitAmountCents int64  `json:"overageUnitAmountCents" db:"overage_unit_amount_cents"`
	Currency               string `json:"currency" db:"currency"`
	IsEnforced             bool   `json:"isEnforced" db:"is_enforced"`
}

type BillingMetrics struct {
	ProfileRuns BillingMetricDetails `json:"profileRuns"`
}

type Billing struct {
	ProjectID           string         `json:"projectID" db:"project_id"`
	Provider            string         `json:"provider" db:"provider"`
	Plan                BillingPlan    `json:"plan" db:"plan"`
	PolarStatus         *string        `json:"polarStatus" db:"polar_status"`
	ExternalCustomerID  string         `json:"externalCustomerID" db:"external_customer_id"`
	PolarCustomerID     *string        `json:"polarCustomerID" db:"polar_customer_id"`
	PolarSubscriptionID *string        `json:"polarSubscriptionID" db:"polar_subscription_id"`
	PolarProductID      *string        `json:"polarProductID" db:"polar_product_id"`
	CurrentPeriodStart  time.Time      `json:"currentPeriodStart" db:"current_period_start"`
	CurrentPeriodEnd    time.Time      `json:"currentPeriodEnd" db:"current_period_end"`
	CancelAtPeriodEnd   bool           `json:"cancelAtPeriodEnd" db:"cancel_at_period_end"`
	CanceledAt          *time.Time     `json:"canceledAt" db:"canceled_at"`
	Metrics             BillingMetrics `json:"metrics"`
}

type BillingCheckoutCreate struct {
	SuccessURL string  `json:"successURL" db:"success_url"`
	ReturnURL  *string `json:"returnURL" db:"return_url"`
	Locale     *string `json:"locale" db:"locale"`
}

func (in *BillingCheckoutCreate) Validate() error {
	v := validator.New()

	in.SuccessURL = strings.TrimSpace(in.SuccessURL)
	if in.SuccessURL == "" {
		v.Add("successURL", "successURL is required")
	} else if parsedURL, err := url.ParseRequestURI(in.SuccessURL); err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		v.Add("successURL", "successURL must be a valid URL")
	}

	if in.ReturnURL != nil {
		trimmed := strings.TrimSpace(*in.ReturnURL)
		if trimmed == "" {
			in.ReturnURL = nil
		} else {
			parsedURL, err := url.ParseRequestURI(trimmed)
			if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
				v.Add("returnURL", "returnURL must be a valid URL")
			}
			*in.ReturnURL = trimmed
		}
	}

	if in.Locale != nil {
		trimmed := strings.TrimSpace(*in.Locale)
		if trimmed == "" {
			in.Locale = nil
		} else {
			*in.Locale = trimmed
		}
	}

	return v.AsError()
}

type BillingSession struct {
	URL       string    `json:"url" db:"url"`
	ExpiresAt time.Time `json:"expiresAt" db:"expires_at"`
}

type BillingPortalCreate struct {
	ReturnURL *string `json:"returnURL" db:"return_url"`
}

func (in *BillingPortalCreate) Validate() error {
	v := validator.New()

	if in.ReturnURL == nil {
		return v.AsError()
	}

	trimmed := strings.TrimSpace(*in.ReturnURL)
	if trimmed == "" {
		in.ReturnURL = nil
		return v.AsError()
	}

	parsedURL, err := url.ParseRequestURI(trimmed)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		v.Add("returnURL", "returnURL must be a valid URL")
	}

	*in.ReturnURL = trimmed

	return v.AsError()
}

type BillingUsageOutboxItem struct {
	ID               string          `json:"id" db:"id"`
	ProjectID        string          `json:"projectID" db:"project_id"`
	MetricKey        string          `json:"metricKey" db:"metric_key"`
	SourceEntityKind string          `json:"sourceEntityKind" db:"source_entity_kind"`
	SourceEntityID   string          `json:"sourceEntityID" db:"source_entity_id"`
	Quantity         int64           `json:"quantity" db:"quantity"`
	OccurredAt       time.Time       `json:"occurredAt" db:"occurred_at"`
	Payload          json.RawMessage `json:"payload" db:"payload"`
	AttemptCount     int             `json:"attemptCount" db:"attempt_count"`
	NextAttemptAt    time.Time       `json:"nextAttemptAt" db:"next_attempt_at"`
	LastError        *string         `json:"lastError" db:"last_error"`
	SentAt           *time.Time      `json:"sentAt" db:"sent_at"`
	CreatedAt        time.Time       `json:"createdAt" db:"created_at"`
	UpdatedAt        time.Time       `json:"updatedAt" db:"updated_at"`

	Metric BillingMetric `json:"metric" db:"metric"`
}

type BillingWebhookEvent struct {
	ID              string          `json:"id" db:"id"`
	Provider        string          `json:"provider" db:"provider"`
	PolarEventID    string          `json:"polarEventID" db:"polar_event_id"`
	PolarEventKind  string          `json:"polarEventKind" db:"polar_event_kind"`
	PolarPayload    json.RawMessage `json:"polarPayload" db:"polar_payload"`
	ReceivedAt      time.Time       `json:"receivedAt" db:"received_at"`
	ProcessedAt     *time.Time      `json:"processedAt" db:"processed_at"`
	ProcessingError *string         `json:"processingError" db:"processing_error"`
	CreatedAt       time.Time       `json:"createdAt" db:"created_at"`
	UpdatedAt       time.Time       `json:"updatedAt" db:"updated_at"`
}

func ExternalCustomerIDForProject(projectID string) string {
	return "project:" + projectID
}
