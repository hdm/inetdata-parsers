package utils

import "testing"

func TestReverseKey(t *testing.T) {
	tests := []struct {
		value    string
		expected string
	}{
		{"", ""},
		{"a", "a"},
		{"ab", "ba"},
		{"abc", "cba"},
		{"abcd", "dcba"},
		{"abcde", "edcba"},
		{"abcdef", "fedcba"},
		{"abcdefg", "gfedcba"},
		{"abcdefgh", "hgfedcba"},
	}

	for _, test := range tests {
		v := ReverseKey(test.value)
		if v != test.expected {
			t.Errorf("got %q; want %q", v, test.expected)
		}
	}
}
