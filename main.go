package main

import (
	"Vaverka/cli"
	"Vaverka/rule"
	"Vaverka/scanner"
	"fmt"
	"github.com/spf13/pflag"
	"os"
	"runtime"
	"sync"
)

func main() {
	var isApi bool
	var rList []rule.Rule
	var err error
	var scanErr error                 // errors received from scanner
	errorChan := make(chan error, 10) // buffered channel to avoid blocking
	var scannerWg sync.WaitGroup
	var errorWg sync.WaitGroup // WaitGroup for error processing

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
		// Start a goroutine to handle errors and add it to errorWg
		errorWg.Add(1)
		go func() {
			defer errorWg.Done()
			for scanErr = range errorChan {
				if scanErr != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", scanErr)
				}
			}
		}()

		// Launch a scanner goroutine for each rule
		for _, r := range rList {
			scannerWg.Add(1)
			go func(ruleItem rule.Rule) {
				defer scannerWg.Done()
				scanner.Scan(ruleItem, errorChan)
			}(r)
		}

		// Wait for all scanner goroutines to finish
		scannerWg.Wait()
		// Close the error channel so that error handling goroutine can finish
		close(errorChan)
		// Wait until all errors are processed
		errorWg.Wait()

	default:
		fmt.Fprintf(os.Stderr, "No valid mode or rules specified. Please use 'api' or provide a list of rules.\n")
		os.Exit(1)
	}
}
