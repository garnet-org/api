package types

import (
	"fmt"
	"net/url"
	"strconv"
)

// Page is a generic type for paginated results.
type Page[T any] struct {
	Items    []T      `json:"items"`
	PageInfo PageInfo `json:"pageInfo"`
}

// PageInfo contains pagination information.
type PageInfo struct {
	HasNextPage bool    `json:"hasNextPage"`
	EndCursor   *Cursor `json:"endCursor"`
	HasPrevPage bool    `json:"hasPrevPage"`
	StartCursor *Cursor `json:"startCursor"`
}

// Cursor is a string type used for pagination.
type Cursor string

// PageArgs contains arguments for pagination.
type PageArgs struct {
	First  *uint   `json:"first,omitempty"`
	After  *Cursor `json:"after,omitempty"`
	Last   *uint   `json:"last,omitempty"`
	Before *Cursor `json:"before,omitempty"`
}

// DecodePageArgs extracts PageArgs from URL query parameters.
func DecodePageArgs(v url.Values) PageArgs {
	var first *uint
	f := v.Get("first")
	if f != "" {
		ff, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			panic(err)
		}
		uFirst := uint(ff)
		first = &uFirst
	}

	var last *uint
	l := v.Get("last")
	if l != "" {
		ll, err := strconv.ParseUint(l, 10, 64)
		if err != nil {
			panic(err)
		}
		uLast := uint(ll)
		last = &uLast
	}

	var before *Cursor
	b := v.Get("before")
	if b != "" {
		bf := Cursor(b)
		before = &bf
	}

	var after *Cursor
	a := v.Get("after")
	if a != "" {
		af := Cursor(a)
		after = &af
	}

	return PageArgs{
		First:  first,
		After:  after,
		Last:   last,
		Before: before,
	}
}

// Order is a type for sorting order.
type Order string

const (
	// OrderAsc is ascending order.
	OrderAsc Order = "asc"

	// OrderDesc is descending order.
	OrderDesc Order = "desc"
)

func (o Order) String() string {
	return string(o)
}

// Validate checks if the order struct is valid.
func (o Order) Validate() error {
	switch o {
	case OrderAsc, OrderDesc:
		return nil
	default:
		return fmt.Errorf("invalid order: %s", o)
	}
}

// Sort is a type for sorting results.
type Sort struct {
	// Field is the field to sort by.
	Field string `json:"field"`

	// Order is the order to sort by.
	Order Order `json:"order"`
}

// DecodeSort extracts Sort from URL query parameters.
// It returns nil if something is wrong or missing.
func DecodeSort(v url.Values) *Sort {
	field := v.Get("sort.field")
	order := v.Get("sort.order")

	if field == "" {
		return nil
	}

	s := &Sort{
		Field: field,
		Order: OrderDesc,
	}

	if order != "" {
		s.Order = Order(order)
	}

	return s
}
