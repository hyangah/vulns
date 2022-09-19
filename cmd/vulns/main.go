// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

// vulns is an analysis program that reports import paths
// leading to packages with known vulnerabilities.
package main

import (
	context "context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sort"
	"strings"

	myanalysis "github.com/hyangah/vulns/analysis"
	"github.com/hyangah/vulns/internal/analysisflags"
	"github.com/hyangah/vulns/internal/checker"
	"github.com/hyangah/vulns/internal/govulncheck"
	"github.com/hyangah/vulns/internal/osvutil"
	"github.com/hyangah/vulns/quickcheck"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
)

func main() {
	var a = myanalysis.Analyzer

	log.SetFlags(0)
	log.SetPrefix(a.Name + ": ")

	analyzers := []*analysis.Analyzer{a}

	if err := analysis.Validate(analyzers); err != nil {
		log.Fatal(err)
	}

	checker.RegisterFlags()

	flag.Usage = func() {
		paras := strings.Split(a.Doc, "\n\n")
		fmt.Fprintf(os.Stderr, "%s: %s\n\n", a.Name, paras[0])
		fmt.Fprintf(os.Stderr, "Usage: %s [-flag] [package]\n\n", a.Name)
		if len(paras) > 1 {
			fmt.Fprintln(os.Stderr, strings.Join(paras[1:], "\n\n"))
		}
		fmt.Fprintln(os.Stderr, "\nFlags:")
		flag.PrintDefaults()
	}

	// ASK(adonovan): DO WE NEED to export analysisflags.Parse too??
	analyzers = analysisflags.Parse(analyzers, false)

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if checker.CPUProfile != "" {
		f, err := os.Create(checker.CPUProfile)
		if err != nil {
			log.Fatal(err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal(err)
		}
		// NB: profile won't be written in case of error.
		defer pprof.StopCPUProfile()
	}

	if checker.Trace != "" {
		f, err := os.Create(checker.Trace)
		if err != nil {
			log.Fatal(err)
		}
		if err := trace.Start(f); err != nil {
			log.Fatal(err)
		}
		// NB: trace log won't be written in case of error.
		defer func() {
			trace.Stop()
			log.Printf("To view the trace, run:\n$ go tool trace view %s", checker.Trace)
		}()
	}

	if checker.MemProfile != "" {
		f, err := os.Create(checker.MemProfile)
		if err != nil {
			log.Fatal(err)
		}
		// NB: memprofile won't be written in case of error.
		defer func() {
			runtime.GC() // get up-to-date statistics
			if err := pprof.WriteHeapProfile(f); err != nil {
				log.Fatalf("Writing memory profile: %v", err)
			}
			f.Close()
		}()
	}

	// Load the packages.
	if dbg('v') {
		log.SetPrefix("")
		log.SetFlags(log.Lmicroseconds) // display timing
		log.Printf("load %s", args)
	}
	cfg := &packages.Config{
		Mode:  packages.LoadSyntax | packages.LoadAllSyntax | packages.NeedModule,
		Tests: checker.IncludeTests,
	}
	pkgs, err := load(cfg, args)
	if err != nil {
		if _, ok := err.(typeParseError); !ok {
			// Fail when some of the errors are not
			// related to parsing nor typing.
			log.Print(err)
			os.Exit(1)
		}
		// TODO: filter analyzers based on RunDespiteError?
	}

	dbClient, err := client.NewClient(osvutil.FindGOVULNDB(cfg), client.Options{HTTPCache: govulncheck.DefaultCache()})
	if err != nil {
		exitf("failed to setup vulncheck client: %v", err)
	}
	summary, _, err := quickcheck.Analyze(context.Background(), pkgs, dbClient)

	type entry struct {
		Symbol string
		Trace  []string
		Count  int64
	}
	// id -> package -> entry
	all := map[string]map[string][]entry{}
	for k, v := range summary {
		forID := all[k.ID]
		if forID == nil {
			forID = map[string][]entry{}
			all[k.ID] = forID
		}
		forPkg := forID[k.PackagePath]
		forPkg = append(forPkg, entry{k.Symbol, v.Trace, v.Count})
		forID[k.PackagePath] = forPkg
	}
	var ids []string
	for id := range all {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	count := 0
	for _, id := range ids {
		for pkg, entries := range all[id] {
			count++
			fmt.Printf("Vulnerability #%d: %v (%v)\n", count, id, pkg)
			fmt.Println("\nCall stacks in your code:")
			for _, p := range entries[0].Trace {
				fmt.Printf("\t%v\n", p)
			}
			fmt.Println()
		}
	}
}

func jsonString(v any) string {
	s, _ := json.MarshalIndent(v, " ", " ")
	return string(s)
}

func dbg(b byte) bool { return strings.IndexByte(checker.Debug, b) >= 0 }

func load(cfg *packages.Config, patterns []string) ([]*packages.Package, error) {

	initial, err := packages.Load(cfg, patterns...)
	if err == nil {
		if len(initial) == 0 {
			err = fmt.Errorf("%s matched no packages", strings.Join(patterns, " "))
		} else {
			err = loadingError(initial)
		}
	}
	return initial, err
}

// loadingError checks for issues during the loading of initial
// packages. Returns nil if there are no issues. Returns error
// of type typeParseError if all errors, including those in
// dependencies, are related to typing or parsing. Otherwise,
// a plain error is returned with an appropriate message.
func loadingError(initial []*packages.Package) error {
	var err error
	if n := packages.PrintErrors(initial); n > 1 {
		err = fmt.Errorf("%d errors during loading", n)
	} else if n == 1 {
		err = errors.New("error during loading")
	} else {
		// no errors
		return nil
	}
	all := true
	packages.Visit(initial, nil, func(pkg *packages.Package) {
		for _, err := range pkg.Errors {
			typeOrParse := err.Kind == packages.TypeError || err.Kind == packages.ParseError
			all = all && typeOrParse
		}
	})
	if all {
		return typeParseError{err}
	}
	return err
}

// typeParseError represents a package load error
// that is related to typing and parsing.
type typeParseError struct {
	error
}

func exitf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

func populateVulnsCatalog(pkgs []*packages.Package) {
	cfg := &packages.Config{
		// We need module for analysis.
		Mode:  packages.NeedModule | packages.NeedImports,
		Tests: true,
	}

	dbClient, err := client.NewClient(osvutil.FindGOVULNDB(cfg), client.Options{HTTPCache: govulncheck.DefaultCache()})
	if err != nil {
		exitf("failed to setup vulncheck client: %v", err)
	}
	modvulns, err := osvutil.FetchOSVEntries(context.Background(), dbClient, pkgs)
	if err != nil {
		exitf("failed to fetch OSV entries: %v", err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(modvulns); err != nil {
		exitf("failed to encode module vulnerability info: %v", err)
	}
}

/*
// extractModules returns a new, unordered slice containing
//the modules of all the packages in the import graph rooted at pkgs.
func extractModules(pkgs []*packages.Package) []*packages.Module {
	modMap := map[string]*packages.Module{}

	seen := map[*packages.Package]bool{}
	var extract func(*packages.Package)
	extract = func(pkg *packages.Package) {
		if seen[pkg] {
			return
		}
		if pkg.Module != nil {
			modMap[modKey(pkg.Module)] = pkg.Module
			fmt.Printf("%v -> %v\n", pkg.PkgPath, modKey(pkg.Module))
		} else {
			fmt.Printf("%v -> nil\n", pkg.PkgPath)
		}
		seen[pkg] = true
		for _, imp := range pkg.Imports {
			extract(imp)
		}
	}
	for _, pkg := range pkgs {
		extract(pkg)
	}

	modules := []*packages.Module{}
	for _, mod := range modMap {
		modules = append(modules, mod)
	}
	return modules
}
*/
