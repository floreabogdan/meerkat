// Command meerkat is a Suricata console: it follows eve.json, enriches each
// alert with ASN/country/city, stores it in SQLite, and serves a web UI whose
// home page is a list of SOURCE ADDRESSES rather than a list of events —
// first/last seen, alert count, distinct signatures, distinct ports, worst
// severity, triage state. A router that emits 891 alerts in four minutes from a
// few dozen addresses does not need a faster log viewer; it needs the log rolled
// up into decisions. Run `meerkat init` once, then `meerkat server` (normally
// under systemd).
//
// Named for Suricata suricatta, the meerkat: the sentry that stands watch and
// alarm-calls. Sister projects: birdy (BIRD), nftably (nftables).
package main

import (
	"fmt"
	"os"

	"github.com/floreabogdan/meerkat/internal/buildinfo"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "lookup":
		err = cmdLookup(os.Args[2:])
	case "passwd":
		err = cmdPasswd(os.Args[2:])
	case "rules":
		err = cmdRules(os.Args[2:])
	case "server":
		err = cmdServer(os.Args[2:])
	case "version":
		fmt.Println("meerkat " + buildinfo.Version)
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "meerkat: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "meerkat:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `meerkat — a Suricata console

Usage:
  meerkat init [flags]     create the database and admin account
  meerkat doctor [flags]   check eve.json, Suricata, the geo databases and nftably
  meerkat passwd [flags]   set an account's password
  meerkat lookup <ip>      print what the geo databases produce for an address
  meerkat rules <cmd>      manage Suricata's ruleset (status, index, apply)
  meerkat server [flags]   follow eve.json and serve the console
  meerkat version          print the version

Run "meerkat <command> -h" for flags on a specific command.
`)
}
