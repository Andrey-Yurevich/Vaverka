package cli

import (
	"Vaverka/rule"
	"Vaverka/scanner"
	"errors"
	"fmt"
	"runtime"
	"slices"
)

func ParseArguments(PositionalArgs []string) (bool, []rule.Rule, error) {
	var err error

	var rList []rule.Rule

	switch {
	case len(PositionalArgs) == 0:
		return false, nil, errors.New("no arguments received")

	case PositionalArgs[0] == "api" && len(PositionalArgs) == 1:
		return true, nil, nil

	case len(PositionalArgs) >= 1 && !slices.Contains(PositionalArgs, "api"):
		var r rule.Rule
		for _, ruleString := range PositionalArgs[:] {
			r, err = rule.ParseRule(ruleString)
			if err != nil {
				return false, nil, fmt.Errorf("\"%s\" is not correct rule", ruleString)
			}
			rList = append(rList, r)
		}

		return false, rList, nil
	default:
		return false, nil, errors.New("invalid input. Please enter either a list of rules or “api” to enable API mode")
	}
}

func ParseGlobalOptionsFlags(pps *int, threads *int) {
	if *pps > 0 {
		scanner.MaxPPS = *pps
	}

	if *threads > 0 {
		runtime.GOMAXPROCS(*threads)
	}

}
