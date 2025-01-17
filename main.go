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
	var scanErr error // errors receives specifically from scanner
	// Initialize the error channel
	errorChan := make(chan error)
	var scannerWg sync.WaitGroup

	Pps := pflag.Int("pps", 4096, "Maximum PPS for instance. The maximum outgoing packets quantity can't be higher than this value.")
	Threads := pflag.Int("threads", runtime.GOMAXPROCS(0), "Number of threads")
	pflag.Parse()

	isApi, rList, err = cli.ParseArguments(pflag.Args())
	if err != nil {
		_, err = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		if err != nil {
			panic(err)
		}
		return
	}

	err = cli.ParseGlobalOptionsFlags(Pps, Threads)
	if err != nil {
		panic(err)
	}

	switch {
	case isApi:
		fmt.Println("Starting Vaverka in Api mode")
		os.Exit(0)

	case len(rList) > 0:
		// Start a goroutine to handle errors from the error channel
		go func() {
			for scanErr = range errorChan {
				if scanErr != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", scanErr)
				}
			}
		}()

		// Launch a scanner goroutine for each rule
		for _, r := range rList {
			scannerWg.Add(1) // Add to the WaitGroup before starting the goroutine
			go func(ruleItem rule.Rule) {
				defer scannerWg.Done()
				scanner.VerticalPortScanner(ruleItem, errorChan)
			}(r)
		}

		// Close the error channel after all scanners are done
		go func() {
			scannerWg.Wait()
			close(errorChan)
		}()

		// Wait for all scanner goroutines to finish
		scannerWg.Wait()

	default:
		_, err = fmt.Fprintf(os.Stderr, "No valid mode or rules specified. Please use 'api' or provide a list of rules.\n")
		if err != nil {
			panic(err)
		}
	}
}
