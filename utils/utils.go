package utils

import "golang.org/x/exp/slices"

func ReversedSlices[T any](s []T) []T {
	s1 := slices.Clone(s)
	slices.Reverse(s1)
	return s1
}
