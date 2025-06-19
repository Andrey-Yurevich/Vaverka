package main

import (
	"Vaverka/cli"
	"Vaverka/rule"
	"Vaverka/scanner"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/spf13/pflag"
)

func main() {
	var isApi bool
	var rList []rule.Rule
	var err error
	var scanErrors []error
	var mu sync.Mutex
	var scannerWg sync.WaitGroup

	Pps := pflag.Int("pps", 4096, "Maximum PPS for instance. The maximum outgoing packets quantity can't be higher than this value.")
	Threads := pflag.Int("threads", runtime.GOMAXPROCS(0), "Number of threads")
	pflag.Parse()

	isApi, rList, err = cli.ParseArguments(pflag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	err = cli.ParseGlobalOptionsFlags(Pps, Threads)
	if err != nil {
		panic(err)
	}

	switch {
	case isApi:
		fmt.Println("Starting Vaverka in API mode")
		os.Exit(0)

	case len(rList) > 0:

		for _, r := range rList {
			scannerWg.Add(1)
			go func(ruleItem rule.Rule) {
				defer scannerWg.Done()
				if err = scanner.Scan(ruleItem); err != nil {
					mu.Lock()
					scanErrors = append(scanErrors, err)
					mu.Unlock()
				}
			}(r)
		}

		scannerWg.Wait()

		for _, scanErr := range scanErrors {
			fmt.Fprintf(os.Stderr, "Error: %v\n", scanErr)
		}

	default:
		fmt.Fprintf(os.Stderr, "No valid mode or rules specified. Please use 'api' or provide a list of rules.\n")
		os.Exit(1)
	}
}
