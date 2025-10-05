package cli

import (
	"Vaverka/constants"
	"Vaverka/rule"
	"Vaverka/scanner"
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/time/rate"
)

func ParseArguments(PositionalArgs []string) ([]rule.Rule, error) {
	var err error

	var rList []rule.Rule

	switch {
	case len(PositionalArgs) == 0:
		return nil, errors.New("no arguments received")

	case len(PositionalArgs) >= 1:
		var r rule.Rule
		for _, ruleString := range PositionalArgs[:] {
			r, err = rule.ParseRule(ruleString)
			if err != nil {
				return nil, fmt.Errorf("error occured while parsing rule: %s", err)
			}
			rList = append(rList, r)
		}

		return rList, nil
	default:
		return nil, errors.New("invalid input. Please enter either a list of rules")
	}
}

func ParseGlobalOptionsFlags(pps *int, threads *int) error {
	if *pps > constants.IOVecPacketsChunkSize {
		scanner.Limiter = rate.NewLimiter(rate.Limit(*pps/constants.IOVecPacketsChunkSize), constants.LimiterBuffersBurstLimit)
	} else {
		return errors.New(fmt.Sprintf("PPS must be higher then %d", constants.IOVecPacketsChunkSize))
	}

	if *threads > 0 {
		runtime.GOMAXPROCS(*threads)
	}
	return nil
}
