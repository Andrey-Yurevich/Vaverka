package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/Andrey-Yurevich/Vaverka/cli"
	"github.com/Andrey-Yurevich/Vaverka/constants"
	"github.com/Andrey-Yurevich/Vaverka/rule"

	"github.com/spf13/pflag"
)

func main() {
	var rList []rule.Rule
	var err error

	Pps := pflag.Uint64("pps", constants.DefaultGlobalPpsLimit, "Maximum PPS for instance. The maximum outgoing packets quantity can't be higher than this value.")
	Threads := pflag.Int("threads", runtime.GOMAXPROCS(0), "Number of threads")
	pflag.Parse()

	rList, err = cli.ParseArguments(pflag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while parsing arguments: %v\n", err)
		os.Exit(1)
	}

	var delayNeeded bool
	for i := 0; i < len(rList); i++ {
		if rList[i].Options.Pps > *Pps {
			fmt.Fprintf(os.Stderr,
				"\033[41m{\"warning\":\"Rule PPS (%d) exceeds global limit (%d); actual rate = %d. Use --pps to change it. Scan starts in 5 s.\"}\033[0m\n",
				rList[i].Options.Pps, *Pps, *Pps)
			delayNeeded = true
		}
	}
	if delayNeeded {
		time.Sleep(time.Second * 5)
	}

	err = cli.ParseGlobalOptionsFlags(Pps, Threads)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while parsing flags: %v\n", err)
	}

	cli.InteractiveScan(rList)
}
