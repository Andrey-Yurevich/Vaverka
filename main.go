package main

import (
	"Vaverka/cli"
	"Vaverka/rule"
	"Vaverka/scanner"
	"fmt"
	"github.com/spf13/pflag"
	"os"
	"runtime"
)

func main() {
	var isApi bool
	var rList []rule.Rule
	var err error

	Pps := pflag.Int("pps", 2048, "Maximum PPS for instance. The maximum outgoing packets quantity can't be higher then this value.")
	Threads := pflag.Int("threads", runtime.GOMAXPROCS(0), "Number of threads")

	pflag.Parse()

	isApi, rList, err = cli.ParseArguments(pflag.Args())

	if err != nil {
		//panic(fmt.Errorf("incorrect command line arguments. Please refer to the help page.\n %s", err))
		_, err = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		if err != nil {
			panic(err)
		}
	}

	err = cli.ParseGlobalOptionsFlags(Pps, Threads)
	if err != nil {
		panic(err)
	}

	switch {
	case isApi:
		fmt.Println("Starting Vaverka in Api mode")
		os.Exit(0)
	case rList != nil && len(rList) > 0:
		for _, r := range rList {
			err = scanner.VerticalPortScanner(r)
			if err != nil {
				panic(err)
			}
		}
	default:
		_, err = fmt.Fprintf(os.Stderr, "No valid mode or rules specified. Please use 'api' or provide a list of rules. Error: %v\n", err)
		if err != nil {
			panic(err)
		}
	}
}
