package main

import (
	"os"

	"github.com/safing/portbase/info"
	"github.com/safing/portbase/run"
	"github.com/safing/spn/conf"

	// include packages here
	_ "github.com/safing/portbase/modules/subsystems"
	_ "github.com/safing/portmaster/core"
	_ "github.com/safing/portmaster/firewall"
	_ "github.com/safing/portmaster/firewall/inspection/encryption"
	_ "github.com/safing/portmaster/nameserver"
	_ "github.com/safing/portmaster/ui"
	_ "github.com/safing/spn/captain"
)

func main() {
	// set information
	info.Set("Portmaster", "0.5.7", "AGPLv3", true)

	// enable SPN client mode
	conf.EnableClient(true)

	// start
	os.Exit(run.Run())
}
