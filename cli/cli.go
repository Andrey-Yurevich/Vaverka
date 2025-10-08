package cli

import (
	"Vaverka/constants"
	"Vaverka/rule"
	"Vaverka/scanner"
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/time/rate"
)

func printPortInfo(p scanner.Port) {
	fmt.Printf(
		"{%s\"port\"%s: %s%d%s, %s\"host\"%s: %s\"%s\"%s, %s\"state\"%s: %s\"open\"%s, %s\"type\"%s: %s\"%s\"%s, %s\"service\"%s: %s\"%s\"%s}\n",
		// "port" key in blue
		ColorBlue, ColorReset,
		// port value in green
		ColorGreen, p.Port, ColorReset,

		// "host" key in blue
		ColorBlue, ColorReset,
		// host value in green
		ColorGreen, p.Host, ColorReset,

		// "state" key in blue
		ColorBlue, ColorReset,
		// state value in green
		ColorGreen, ColorReset,

		// "type" key in blue
		ColorBlue, ColorReset,
		// type value in green
		ColorGreen, p.Protocol, ColorReset,

		// "service" key in blue
		ColorBlue, ColorReset,
		// service value in green
		ColorGreen, p.Service, ColorReset,
	)
}

func printDiscovery(h scanner.Host) {
	fmt.Printf(
		"{%s\"host\"%s: %s\"%s\"%s, %s\"state\"%s: %s\"%s\"%s, %s\"technique\"%s: %s\"%s\"%s, %s\"network\"%s: %s\"%s\"%s,%s\"mac\"%s: %s\"%s\"%s}\n",
		// "host" key in blue
		ColorBlue, ColorReset,
		// host value in green
		ColorGreen, h.IP, ColorReset,

		// "state" key in blue
		ColorBlue, ColorReset,
		// state value in green
		ColorGreen, h.State, ColorReset,

		// "technique" key in blue
		ColorBlue, ColorReset,
		// technique value in green
		ColorGreen, h.Technique, ColorReset,

		// "network" key in blue
		ColorBlue, ColorReset,
		// network value in green
		ColorGreen, h.Network.String(), ColorReset,

		// "mac" key in blue
		ColorBlue, ColorReset,
		// mac value in green
		ColorGreen, h.Mac.String(), ColorReset,
	)
}

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
				return nil, fmt.Errorf("error occurred while parsing rule: %s", err)
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

func InteractiveScan(rList []rule.Rule) {
	if len(rList) == 0 {
		fmt.Fprintln(os.Stderr, "No valid mode or rules specified. Please provide a list of rules.")
		os.Exit(1)
	}

	for _, r := range rList {
		findingsChan, errChan, err := scanner.Scan(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while initiating scan of network %s: %v\n", r.Network, err)
			os.Exit(1)
		}

	Outer:
		for {
			select {
			case f, ok := <-findingsChan:
				if !ok {
					break Outer
				}

				switch v := f.(type) {
				case scanner.Host:
					printDiscovery(v)
				case scanner.Port:
					printPortInfo(v)
				}
			case e, ok := <-errChan:
				if !ok {
					break Outer
				}
				fmt.Fprintf(os.Stderr, "Error while scanning network %s: %v\n", r.Network, e)
			}
		}
	}
}
