package main

// Based on the offical Go examples from
// https://github.com/golang/sys/blob/master/windows/svc/example
// by The Go Authors.
// Original LICENSE (sha256sum: 2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067) can be found in vendor/pkg cache directory.

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

var (
	runCoreService = &cobra.Command{
		Use:   "core-service",
		Short: "Run the Portmaster Core as a Windows Service",
		RunE: runAndLogControlError(func(cmd *cobra.Command, args []string) error {
			return runService(cmd, &Options{
				Identifier:        "core/portmaster-core",
				AllowDownload:     true,
				AllowHidingWindow: false,
				NoOutput:          true,
			})
		}),
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			// UnknownFlags will ignore unknown flags errors and continue parsing rest of the flags
			UnknownFlags: true,
		},
	}

	// wait groups
	runWg    sync.WaitGroup
	finishWg sync.WaitGroup
)

func init() {
	runCmd.AddCommand(runCoreService)
}

const serviceName = "PortmasterCore"

type windowsService struct{}

func (ws *windowsService) Execute(args []string, changeRequests <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

service:
	for {
		select {
		case <-startupComplete:
			changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
		case <-shuttingDown:
			changes <- svc.Status{State: svc.StopPending}
			break service
		case c := <-changeRequests:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				initiateShutdown(nil)
			default:
				log.Printf("unexpected control request: #%d\n", c)
			}
		}
	}

	// define return values
	if getShutdownError() != nil {
		ssec = true // this error is specific to this service (ie. custom)
		errno = 1   // generic error, check logs / windows events
	}

	// wait until everything else is finished
	finishWg.Wait()
	// send stopped status
	changes <- svc.Status{State: svc.Stopped}
	// wait a little for the status to reach Windows
	time.Sleep(100 * time.Millisecond)
	return
}

func runService(cmd *cobra.Command, opts *Options) error {
	// check if we are running interactively
	isDebug, err := svc.IsAnInteractiveSession()
	if err != nil {
		return fmt.Errorf("could not determine if running interactively: %s", err)
	}
	// select service run type
	svcRun := svc.Run
	if isDebug {
		log.Printf("WARNING: running interactively, switching to debug execution (no real service).\n")
		svcRun = debug.Run
	}

	// open eventlog
	elog, err := eventlog.Open(serviceName)
	if err != nil {
		return fmt.Errorf("failed to open eventlog: %s", err)
	}
	defer elog.Close()

	runWg.Add(2)
	finishWg.Add(1)

	// run service client
	go func() {
		sErr := svcRun(serviceName, &windowsService{})
		initiateShutdown(sErr)
		runWg.Done()
	}()

	// run service
	go func() {
		// run slightly delayed
		time.Sleep(250 * time.Millisecond)
		handleRun(cmd, opts)
		finishWg.Done()
		runWg.Done()
	}()

	runWg.Wait()

	err = getShutdownError()
	if err != nil {
		log.Printf("%s service experienced an error: %s\n", serviceName, err)
		elog.Error(1, fmt.Sprintf("%s experienced an error: %s", serviceName, err))
	}

	return err
}