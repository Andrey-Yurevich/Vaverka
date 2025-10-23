package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/Andrey-Yurevich/Vaverka/cli"
	"github.com/Andrey-Yurevich/Vaverka/constants"
	"github.com/Andrey-Yurevich/Vaverka/rule"

	"github.com/spf13/pflag"
)

func main() {
	var rList []rule.Rule
	var err error

	Pps := pflag.Uint64("pps", constants.DefaultPpsLimit, "Maximum PPS for instance. The maximum outgoing packets quantity can't be higher than this value.")
	Threads := pflag.Int("threads", runtime.GOMAXPROCS(0), "Number of threads")
	pflag.Parse()

	rList, err = cli.ParseArguments(pflag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while parsing arguments: %v\n", err)
		os.Exit(1)
	}

	err = cli.ParseGlobalOptionsFlags(Pps, Threads)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while parsing flags: %v\n", err)
	}

	cli.InteractiveScan(rList)
}
