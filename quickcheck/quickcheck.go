// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package quickcheck is an experimental vulnerability scanning
// library based on a simple reference graph analysis.
// For accurate results, golang.org/x/vuln/vulncheck is recommended.
package quickcheck

import (
	"context"
	"fmt"
	"strings"

	vulnsanalysis "github.com/hyangah/vulns/analysis"
	"github.com/hyangah/vulns/internal/checker"
	"github.com/hyangah/vulns/internal/osvutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
)

type Vuln struct {
	ID            string
	Symbol        string
	PackagePath   string
	ModulePath    string
	ReferencePath []string
}

type Key struct {
	ID          string // VulnDB ID
	Symbol      string
	PackagePath string
	ModulePath  string
}
type Value struct {
	Trace []string
	Count int64
}

// Analyze runs the reference graph analysis on the given packages.
// The provided packages need to be loaded at least with
// packages.NeedImports | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedModule
//
// * WARNING: due to the current analysis framework's limitation,
// this function first writes the OSV entries to the disk first
// and let the analyzer read them from the file back.
func Analyze(ctx context.Context, pkgs []*packages.Package, dbClient client.Client) (map[Key]Value, map[string][]*osv.Entry, error) {
	var a = vulnsanalysis.Analyzer // singleton!
	analyzers := []*analysis.Analyzer{a}

	pkg2vulns, err := osvutil.FetchOSVEntries(ctx, dbClient, pkgs)
	if err != nil {
		return nil, nil, err
	}
	if len(pkg2vulns) == 0 {
		return nil, nil, nil
	}
	vulnsJSONFile, err := vulnsanalysis.DumpVulnInfo(pkg2vulns)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare vulns-json file (%d vulns): %v)", len(pkg2vulns), err)
	}

	// Print the results.
	a.Flags.Set("vulns-json", vulnsJSONFile)

	results := checker.Analyze(pkgs, analyzers)

	summary := make(map[Key]Value)

	for _, r := range results {
		// ASK(adonovan): can we make Diagnostics carry arbitrary
		// serializable data in Diagnostics? Here it would be nice
		// I could just carry structured data (package, symbol, path, ...)
		for _, d := range r.Diagnostics {
			// Category carries ID:packagepath.symbol info.
			id, objname, found := strings.Cut(d.Category, ":")
			if !found {
				panic(fmt.Sprintf("invalid diagnostics category obeserved: %+v", d))
			}
			pkgpath, name := parseObjectNameStr(objname)
			modpath := ""
			if vul := pkg2vulns[pkgpath]; len(vul) > 0 {
				modpath = vul[0].Affected[0].Package.Name
			}
			key := Key{ID: id, ModulePath: modpath, PackagePath: pkgpath, Symbol: name}
			value, ok := summary[key]
			if !ok {
				entries := strings.Split(d.Message, "\t")
				value = Value{Trace: entries, Count: 1}
			} else {
				value.Count++
				// Replace the previous value only if the new one is shorter.
				if len(value.Trace) > strings.Count(d.Message, "\t") {
					value.Trace = strings.Split(d.Message, "\t")
				}
			}
			summary[key] = value
		}
	}
	return summary, pkg2vulns, nil
}

func parseObjectNameStr(unquotedName string) (pkgpath, name string) {
	lastSlash := strings.LastIndex(unquotedName, "/")
	if lastSlash < 0 {
		return "", unquotedName
	}
	before, after := unquotedName[:lastSlash], unquotedName[lastSlash:]
	beforeDot, afterDot, found := strings.Cut(after, ".")
	if !found {
		return "", unquotedName
	}
	return before + beforeDot, afterDot
}
