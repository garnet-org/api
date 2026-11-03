package types

import (
	"fmt"

	"github.com/garnet-org/api/validator"
)

const maxPageSize = 200

type CursorPage[T any] struct {
	Items    []T            `json:"items" desc:"Items in the current page"`
	PageInfo CursorPageInfo `json:"pageInfo" desc:"Pagination metadata"`
}

type CursorPageInfo struct {
	TotalCount      uint    `json:"totalCount" desc:"Total number of items matching the query"`
	EndCursor       *string `json:"endCursor" desc:"Cursor of the last item in the page"`
	HasNextPage     bool    `json:"hasNextPage" desc:"Whether there are more items after this page"`
	StartCursor     *string `json:"startCursor" desc:"Cursor of the first item in the page"`
	HasPreviousPage bool    `json:"hasPreviousPage" desc:"Whether there are more items before this page"`
}

type CursorPageArgs struct {
	First  *uint   `json:"first,omitempty" desc:"Number of items to return from the beginning (1-200)"`
	After  *string `json:"after,omitempty" desc:"Cursor to fetch items after"`
	Last   *uint   `json:"last,omitempty" desc:"Number of items to return from the end (1-200)"`
	Before *string `json:"before,omitempty" desc:"Cursor to fetch items before"`
}

func (args CursorPageArgs) IsBackwards() bool {
	return args.Last != nil || args.Before != nil
}

func (args *CursorPageArgs) Validator() *validator.Validator {
	v := validator.New()

	if args.First != nil {
		if *args.First == 0 {
			v.Add("first", "first must be greater than 0")
		} else if *args.First > maxPageSize {
			v.Add("first", fmt.Sprintf("first cannot be greater than %d", maxPageSize))
		}
	}

	if args.Last != nil {
		if *args.Last == 0 {
			v.Add("last", "last must be greater than 0")
		} else if *args.Last > maxPageSize {
			v.Add("last", fmt.Sprintf("last cannot be greater than %d", maxPageSize))
		}
	}

	if args.First != nil && args.Last != nil {
		v.Add("pagination", "cannot specify both first and last")
	}

	return v
}
