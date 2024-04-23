package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"dauthi/charges"
	"dauthi/utils"
)

const (
	banner = `
     ;                                                               
     ED.                                                             
     E#Wi                     :                                   
     E###G.                   Ef                 .    .       t  
     E#fD#W;              ..  E#t     GEEEEEEEL  Di   Dt      Ej 
     E#t t##L            ;W,  E#t     ,;;L#K;;.  E#i  E#i     E#,
     E#t  .E#K,         j##,  E#t        t#E     E#t  E#t     E#t
     E#t    j##f       G###,  E#t fi     t#E     E#t  E#t     E#t
     E#t    :E#K:    :E####,  E#t L#j    t#E     E########f.  E#t
     E#t   t##L     ;W#DG##,  E#t L#L    t#E     E#j..K#j...  E#t
     E#t .D#W;     j###DW##,  E#tf#E:    t#E     E#t  E#t     E#t
     E#tiW#G.     G##i,,G##,  E###f      t#E     E#t  E#t     E#t
     E#K##i     :K#K:   L##,  E#K,       t#E     f#t  f#t     E#t
     E##D.     ;##D.    L##,  EL          fE      ii   ii     E#t
     E#t       ,,,      .,,   :            :                  ,;.
     L:                                                          
                                                   @emptynebuli
     `

	usage = `
  Usage:
    dauthi <charge> <method> [OPTIONS] <dom/corpid/endpoint/cipherTXT> <file>
    dauthi [charge] -h | -help
    dauthi -v

  Global Options:
    -d                     Enable debug output (incremental -ddd)
    -h, -help              Show usage
    -hh                    Extended help
    -p                     User password value
    -r                     Disable randomize device ID
    -s                     Silent - disable banner output
    -t                     Application threads [default: 10]
    -u                     Username value
    -v, -version           Version details

    -proxy                 SOCKS5 proxy IP and port for traffic tunneling (aka 127.0.0.1:8081)
    -retry                 Number of retry attempts on failed connections [default: 1]
    -sleep                 Sleep timer per thread groups in Seconds (aka 3)
    -uuid                  Device UUID value

    <dom>                  Target FQDN for Discovery
    <endpoint>             MDM Authentication Endpoint
    <cipherTXT>            Encrypted CipherTXT
    <file>                 Line divided file containing brute-force values
`

	version = `1.0`
)

func main() {
	// Global program variable definitions
	var (
		flMDMA     string
		flMethod   string
		flAgent    = flag.String("a", "", "")
		flCookie   = flag.String("c", "", "")
		flDebug    = flag.Bool("d", false, "")
		flEmail    = flag.String("email", "", "")
		flGID      = flag.String("gid", "", "")
		flGUID     = flag.Int("guid", 0, "")
		flHelpPP   = flag.Bool("hh", false, "")
		flPIN      = flag.String("pin", "", "")
		flPass     = flag.String("p", "", "")
		flPort     = flag.String("P", "", "")
		flPri      = flag.String("pri", "", "")
		flProxy    = flag.String("proxy", "", "")
		flPub      = flag.String("pub", "", "")
		flRetry    = flag.Int("retry", 1, "")
		flRUUID    = flag.Bool("r", true, "")
		flSilent   = flag.Bool("s", false, "")
		flSleep    = flag.Int("sleep", 0, "")
		flSubGID   = flag.String("sgid", "", "")
		flSubGINT  = flag.Int("sint", 0, "")
		flTenant   = flag.String("tenant", "", "")
		flThread   = flag.Int("t", 10, "")
		flUUID     = flag.String("uuid", "", "")
		flUser     = flag.String("u", "", "")
		flVDebug   = flag.Bool("dd", false, "")
		flVVDebug  = flag.Bool("ddd", false, "")
		flVersion  = flag.Bool("v", false, "")
		flVersion2 = flag.Bool("version", false, "")
	)

	// Flag Usage definition
	flag.Usage = func() {
		if !*flSilent {
			fmt.Println(banner)
		}
		fmt.Println(usage, charges.Usage(flMDMA))
		os.Exit(0)
	}

	// Flags requires first argument to be of -value context to parse correctly
	// Flags will count the arg length with offset +1
	if len(os.Args) > 1 {
		if os.Args[1] == "disco" {
			flMDMA = os.Args[1]
			os.Args = os.Args[1:]
		} else if len(os.Args) < 2 {
			fmt.Printf("%s%s[ERROR] Unrecognized Option ", banner, usage)
			os.Exit(1)
		} else if !strings.HasPrefix(os.Args[1], "-") && !strings.HasPrefix(os.Args[2], "-") {
			flMDMA = os.Args[1]
			flMethod = os.Args[2]
			os.Args = os.Args[2:]
		} else if !strings.HasPrefix(os.Args[1], "-") {
			flMDMA = os.Args[1]
			os.Args = os.Args[1:]
		}
	}

	// Flag Parsing
	flag.Parse()
	if *flVersion || *flVersion2 {
		fmt.Printf("version: %s\n", version)
		os.Exit(0)
	}
	if *flHelpPP {
		if !*flSilent {
			fmt.Println(banner)
		}
		fmt.Println(usage, charges.Usage("full"))
		os.Exit(0)
	}

	opts := &utils.ChargeOpts{
		Agent:       *flAgent,
		Cookie:      *flCookie,
		Email:       *flEmail,
		GUID:        *flGUID,
		GroupID:     *flGID,
		Method:      flMethod,
		PIN:         *flPIN,
		Password:    *flPass,
		Port:        *flPort,
		PriKey:      *flPri,
		Proxy:       *flProxy,
		PubCert:     *flPub,
		RUUID:       *flRUUID,
		Retry:       *flRetry,
		Silent:      *flSilent,
		Sleep:       *flSleep,
		SubGroup:    *flSubGID,
		SubGroupINT: *flSubGINT,
		Tenant:      *flTenant,
		Threads:     *flThread,
		UUID:        *flUUID,
		UserName:    *flUser,
	}

	switch len(flag.Args()) {
	case 1:
		opts.Endpoint = flag.Arg(0)
	case 2:
		opts.Endpoint = flag.Arg(0)
		opts.File = flag.Arg(1)
	default:
		flag.Usage()
	}

	// Increase Debug verbosity
	if *flVVDebug {
		opts.Debug = 3
	} else if *flVDebug {
		opts.Debug = 2
	} else if *flDebug {
		opts.Debug = 1
	} else {
		opts.Debug = 0
	}

	if !*flSilent {
		fmt.Println(banner)
	}

	mdma := charges.Init(flMDMA, opts)
	if ok := mdma == nil; !ok {
		mdma.Call()
	} else if flMDMA != "disco" {
		fmt.Println(usage + charges.Usage(opts.Endpoint) + "[ERROR] Unknown Charge")
	}
}
