package cli

import (
	"Vaverka/constants"
	"Vaverka/rule"
	"Vaverka/scanner"
	"errors"
	"fmt"
	"golang.org/x/time/rate"
	"runtime"
)

func ParseArguments(PositionalArgs []string) (bool, []rule.Rule, error) {
	var err error

	var rList []rule.Rule

	switch {
	case len(PositionalArgs) == 0:
		return false, nil, errors.New("no arguments received")

	case PositionalArgs[0] == "api" && len(PositionalArgs) == 1:
		return true, nil, nil

	case len(PositionalArgs) >= 1 && PositionalArgs[0] != "api":
		var r rule.Rule
		for _, ruleString := range PositionalArgs[:] {
			r, err = rule.ParseRule(ruleString)
			if err != nil {
				return false, nil, fmt.Errorf("error occured while parsing rule: %s", err)
			}
			rList = append(rList, r)
		}

		return false, rList, nil
	default:
		return false, nil, errors.New("invalid input. Please enter either a list of rules or “api” to enable API mode")
	}
}

func ParseGlobalOptionsFlags(pps *int, threads *int) error {
	if *pps > constants.IOVecPacketsChunkSize {
		scanner.Limiter = rate.NewLimiter(rate.Limit(*pps/constants.IOVecPacketsChunkSize), constants.BuffersBurstLimit)
	} else {
		return errors.New(fmt.Sprintf("PPS must be higher then %d", constants.IOVecPacketsChunkSize))
	}

	if *threads > 0 {
		runtime.GOMAXPROCS(*threads)
	}
	return nil
}
