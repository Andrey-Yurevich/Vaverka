package cli

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/Andrey-Yurevich/Vaverka/rule"
	"github.com/Andrey-Yurevich/Vaverka/scanner"
)

func printPortInfo(p scanner.Port) {
	fmt.Printf(
		"{%s\"port\"%s: %s%d%s, %s\"host\"%s: %s\"%s\"%s, %s\"state\"%s: %s\"open\"%s, %s\"type\"%s: %s\"%s\"%s, %s\"service\"%s: %s\"%s\"%s}\n",
		// "port" key in blue
		colorBlue, colorReset,
		// port value in green
		colorGreen, p.Port, colorReset,

		// "host" key in blue
		colorBlue, colorReset,
		// host value in green
		colorGreen, p.Host, colorReset,

		// "state" key in blue
		colorBlue, colorReset,
		// state value in green
		colorGreen, colorReset,

		// "type" key in blue
		colorBlue, colorReset,
		// type value in green
		colorGreen, p.Protocol, colorReset,

		// "service" key in blue
		colorBlue, colorReset,
		// service value in green
		colorGreen, p.Service, colorReset,
	)
}

func printDiscovery(h scanner.Host) {
	fqdnVal := "null"
	if h.FQDN != "" {
		fqdnVal = fmt.Sprintf("%s\"%s\"%s", colorGreen, h.FQDN, colorReset)
	}

	macVal := "null"
	if h.Mac != nil && len(h.Mac) > 0 {
		macVal = fmt.Sprintf("%s\"%s\"%s", colorGreen, h.Mac.String(), colorReset)
	}

	fmt.Printf(
		"{%s\"host\"%s: %s\"%s\"%s, %s\"fqdn\"%s: %s, %s\"state\"%s: %s\"%s\"%s, %s\"technique\"%s: %s\"%s\"%s, %s\"network\"%s: %s\"%s\"%s, %s\"mac\"%s: %s}\n",
		// "host"
		colorBlue, colorReset,
		colorGreen, h.IP, colorReset,

		// "fqdn"
		colorBlue, colorReset,
		fqdnVal,

		// "state"
		colorBlue, colorReset,
		colorGreen, h.State, colorReset,

		// "technique"
		colorBlue, colorReset,
		colorGreen, h.Technique, colorReset,

		// "network"
		colorBlue, colorReset,
		colorGreen, h.Network.String(), colorReset,

		// "mac"
		colorBlue, colorReset,
		macVal,
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
	err := scanner.SetPps(*pps)
	if err != nil {
		return err
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
		stream, err := scanner.Scan(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while initiating scan of network %s: %v\n", r.Network, err)
			os.Exit(1)
		}

		for f := range stream.Findings {
			switch v := f.(type) {
			case scanner.Host:
				printDiscovery(v)
			case scanner.Port:
				printPortInfo(v)
			}
		}

		if err = stream.Wait(); err != nil {
			fmt.Fprintf(os.Stderr, "Error while scanning network %s: %v\n", r.Network, err)
		}
	}
}
