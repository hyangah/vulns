// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hyangah/vulns/internal/govulncheck"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
)

const usageHdr = `vq: simple vulndb lookup tool

Usage:
  vq id <osv-entry-id>

  vq mod module[@version]
     for vulnerabilities in standard libraries, use 'stdlib'
	 as the module name.

Environments:
  GOVULNDB: vulnerability database. (default: https://vuln.go.dev)
`

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, usageHdr)
	flag.PrintDefaults()
	fmt.Fprintln(out)
}

var (
	flagJSON = flag.Bool("json", false, "output in json format")
)

func main() {
	flag.Usage = usage
	flag.Parse()

	if len(flag.Args()) < 2 {
		exitf("insufficient number of args")
	}

	dbClient, err := client.NewClient(findGOVULNDB(), client.Options{HTTPCache: govulncheck.DefaultCache()})
	if err != nil {
		exitf("failed to setup vulncheck client: %v", err)
	}

	var (
		res [][]*osv.Entry
	)

	ctx := context.Background()
	keys := flag.Args()[1:]
	switch x := flag.Arg(0); x {
	case "id":
		res, err = byID(ctx, dbClient, keys...)
	case "mod":
		res, err = byModule(ctx, dbClient, keys...)
	default:
		exitf("unknown mode: %v", x)
	}
	if err != nil {
		exitf("failed: %v", err)
	}
	if len(res) == 0 {
		fmt.Printf("no entry found\n")
		return
	}
	if *flagJSON {
		toJSON(res)
	} else {
		toText(keys, res)
	}
}

func toJSON(res [][]*osv.Entry) {
	s, _ := json.MarshalIndent(res, " ", " ")
	fmt.Printf("%s\n", s)
}

func toText(keys []string, res [][]*osv.Entry) {
	for i, out := range res {
		if len(out) == 0 {
			fmt.Println()
			fmt.Println("-------------")
			fmt.Println(keys[i])
			fmt.Println("-------------")
			fmt.Println("NOT FOUND")
			continue
		}
		for _, e := range out {
			fmt.Println()
			fmt.Println("-------------")
			fmt.Println(e.ID)
			fmt.Println("-------------")

			fmt.Println(e.Details)
			for _, affecting := range e.Affected {
				for _, p := range affecting.EcosystemSpecific.Imports {
					fmt.Println("Package:", p.Path)
					fmt.Println("Range  :", rangesToText(isStdPackage(affecting.Package.Name), affecting.Ranges))
					fmt.Println("Symbols:", strings.Join(p.Symbols, ", "))
					if goos := p.GOOS; len(goos) > 0 {
						fmt.Println("GOOS   :", strings.Join(goos, ", "))
					}
					if goarch := p.GOARCH; len(goarch) > 0 {
						fmt.Println("GOARCH  :", strings.Join(goarch, ", "))
					}
				}
			}
		}
		fmt.Println()
	}
}

func isStdPackage(pkg string) bool {
	if pkg == "" {
		return false
	}
	// std packages do not have a "." in their path. For instance, see
	// Contains in pkgsite/+/refs/heads/master/internal/stdlbib/stdlib.go.
	if i := strings.IndexByte(pkg, '/'); i != -1 {
		pkg = pkg[:i]
	}
	return !strings.Contains(pkg, ".")
}

func rangesToText(isStd bool, affects osv.Affects) string {
	type pair struct {
		in, fixed string
	}
	var paired []pair
	var current *pair

	prefix := "v"
	if isStd {
		prefix = "go"
	}
	for _, a := range affects {
		for _, e := range a.Events {
			if e.Introduced != "" {
				if current != nil {
					paired = append(paired, *current)
				}
				if e.Introduced == "0" {
					current = &pair{in: e.Introduced}
				} else {
					current = &pair{in: prefix + e.Introduced}
				}
			}
			if e.Fixed != "" {
				if current == nil {
					current = &pair{}
				}
				current.fixed = prefix + e.Fixed
				paired = append(paired, *current)
				current = nil
			}
		}
	}
	if current != nil {
		paired = append(paired, *current)
	}
	var b strings.Builder
	for i, p := range paired {
		if i == 0 {
			fmt.Fprintf(&b, "[%v, %v)", p.in, p.fixed)
		} else {
			fmt.Fprintf(&b, ", [%v, %v)", p.in, p.fixed)
		}
	}
	return b.String()
}

func byID(ctx context.Context, cli client.Client, ids ...string) (res [][]*osv.Entry, _ error) {
	for _, id := range ids {
		e, err := cli.GetByID(ctx, id)
		if err != nil {
			return nil, err
		}
		if e == nil {
			res = append(res, nil)
		} else {
			res = append(res, []*osv.Entry{e})
		}
	}
	return res, nil
}

func byModule(ctx context.Context, cli client.Client, mods ...string) (res [][]*osv.Entry, _ error) {
	for _, mod := range mods {
		name, ver, found := strings.Cut(mod, "@")
		if name == "stdlib" && strings.HasPrefix(ver, "go") {
			ver = "v" + ver[2:]
		}
		e, err := cli.GetByModule(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup info for %q: %v", mod, err)
		}
		if found && ver != "" {
			var filtered []*osv.Entry
		next:
			for _, v := range e {
				for _, a := range v.Affected {
					// A module version is affected if
					//  - it is included in one of the affected version ranges
					//  - and module version is not ""
					//  The latter means the module version is not available, so
					//  we don't want to spam users with potential false alarms.
					if a.Ranges.AffectsSemver(ver) {
						filtered = append(filtered, v)
						continue next
					}
				}
			}
			e = filtered
		}
		res = append(res, e)
	}
	return res, nil
}

func exitf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	usage()
	os.Exit(1)
}

func findGOVULNDB() []string {
	if GOVULNDB := os.Getenv("GOVULNDB"); GOVULNDB != "" {
		return strings.Split(GOVULNDB, ",")
	}
	return []string{"https://vuln.go.dev"}
}
