package main

import (
	"fmt"
	"strings"
)

type stringsType []string

func (ss *stringsType) String() string {
	return fmt.Sprintf("%v", *ss)
}

func (ss *stringsType) Set(v string) error {
	for _, scope := range strings.Split(v, ",") {
		*ss = append(*ss, scope)
	}
	return nil
}

func firstNotEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func countTrue(bools ...bool) int {
	count := 0
	for _, b := range bools {
		if b{
			count++
		}
	}
	return count
}

