package types

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
)

const (
	// DefaultPageSize is the default number of items per page.
	DefaultPageSize = 20
)

// Paginator is a generic type for paginated results using offset-based pagination.
type Paginator[T any] struct {
	Data          []T           `json:"data"`
	PaginatorInfo PaginatorInfo `json:"paginatorInfo"`
}

// PaginatorInfo contains offset-based pagination metadata.
type PaginatorInfo struct {
	Total       int  `json:"total"`       // Total number of items available
	PerPage     int  `json:"perPage"`     // Number of items shown per page
	CurrentPage int  `json:"currentPage"` // Current page number (1-based)
	LastPage    int  `json:"lastPage"`    // Last page number
	From        *int `json:"from,omitempty"` // Index of first item on page (1-based)
	To          *int `json:"to,omitempty"`   // Index of last item on page (1-based)
}

// PageArgs contains arguments for offset-based pagination.
type PageArgs struct {
	Page    *int `json:"page,omitempty"`    // Page number (1-based)
	PerPage *int `json:"perPage,omitempty"` // Items per page
}

// DecodePageArgs extracts PageArgs from URL query parameters.
// Supports: ?page=1&perPage=20.
func DecodePageArgs(v url.Values) PageArgs {
	var page *int
	p := v.Get("page")
	if p != "" {
		pp, err := strconv.Atoi(p)
		if err != nil {
			panic(err)
		}
		page = &pp
	}

	var perPage *int
	pp := v.Get("perPage")
	if pp != "" {
		ppp, err := strconv.Atoi(pp)
		if err != nil {
			panic(err)
		}
		perPage = &ppp
	}

	return PageArgs{
		Page:    page,
		PerPage: perPage,
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

// CalculatePaginatorInfo calculates pagination metadata based on data and parameters.
func CalculatePaginatorInfo(dataLen, total int, page, perPage *int) PaginatorInfo {
	pageValue := 1
	if page != nil {
		pageValue = *page
	}

	perPageValue := DefaultPageSize
	if perPage != nil {
		perPageValue = *perPage
	}

	lastPage := int(math.Ceil(float64(total) / float64(perPageValue)))
	if lastPage == 0 {
		lastPage = 1
	}

	out := PaginatorInfo{
		Total:       total,
		PerPage:     perPageValue,
		CurrentPage: pageValue,
		LastPage:    lastPage,
	}

	if dataLen != 0 {
		from := ((pageValue - 1) * perPageValue) + 1
		to := from + dataLen - 1
		out.From = &from
		out.To = &to
	}

	return out
}
