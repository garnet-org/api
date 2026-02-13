package types

import (
	"fmt"

	"github.com/garnet-org/api/validator"
)

const maxPageSize = 200

type CursorPage[T any] struct {
	Items    []T            `json:"items"`
	PageInfo CursorPageInfo `json:"pageInfo"`
}

type CursorPageInfo struct {
	TotalCount      uint    `json:"totalCount"`
	EndCursor       *string `json:"endCursor"`
	HasNextPage     bool    `json:"hasNextPage"`
	StartCursor     *string `json:"startCursor"`
	HasPreviousPage bool    `json:"hasPreviousPage"`
}

type CursorPageArgs struct {
	First *uint
	After *string

	Last   *uint
	Before *string
}

func (args CursorPageArgs) IsBackwards() bool {
	return args.Last != nil || args.Before != nil
}

func (args *CursorPageArgs) Validator() *validator.Validator {
	v := validator.New()

	if args.First != nil && *args.First > maxPageSize {
		v.Add("first", fmt.Sprintf("first cannot be greater than %d", maxPageSize))
	}

	if args.Last != nil && *args.Last > maxPageSize {
		v.Add("last", fmt.Sprintf("last cannot be greater than %d", maxPageSize))
	}

	if args.First != nil && args.Last != nil {
		v.Add("pagination", "cannot specify both first and last")
	}

	return v
}
