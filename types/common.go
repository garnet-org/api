package types

import "time"

type Created struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"createdAt" db:"created_at"`
}
