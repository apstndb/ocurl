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

func countTrue(bools ...bool) int {
	count := 0
	for _, b := range bools {
		if b {
			count++
		}
	}
	return count
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func orDefault(v string, def string) string {
	if v == "" {
		return def
	}
	return v
}

func splitInitLast(ss []string) ([]string, string) {
	var initSlice []string
	var lastElement string
	if len(ss) > 0 {
		initSlice = ss[:len(ss)-1]
		lastElement = ss[len(ss)-1]
	}
	return initSlice, lastElement
}
