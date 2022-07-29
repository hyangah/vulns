// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

// vulns is an analysis program that reports import paths
// leading to packages with known vulnerabilities.
//
// "vulns dump <package pattern>" runs a helper program
// that fetches vulnerability information from the remote
// or local vulnerability database, selects entries
// relevant to the specified packages, and outputs them
// in the JSON format the vulns analysis can use to prepare
// the known vulnerability list.
package main

import (
	"bytes"
	context "context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strings"

	myanalysis "github.com/hyangah/vulns/analysis"
	"github.com/hyangah/vulns/internal/analysisflags"
	"github.com/hyangah/vulns/internal/checker"
	"github.com/hyangah/vulns/internal/govulncheck"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
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

	dbClient, err := client.NewClient(findGOVULNDB(cfg), client.Options{HTTPCache: govulncheck.DefaultCache()})
	if err != nil {
		exitf("failed to setup vulncheck client: %v", err)
	}

	pkg2vulns, err := fetchOSVEntries(context.Background(), dbClient, pkgs)
	if err != nil {
		exitf("failed to fetch osv entries: %v", err)
	}
	if len(pkg2vulns) == 0 {
		log.Println("zero vulnerability found")
		return
	}
	vulnsJSONFile, err := dumpToFile(pkg2vulns)
	if err != nil {
		exitf("failed to write fetched osv entries: %v", err)
	}

	// Print the results.
	a.Flags.Set("vulns-json", vulnsJSONFile)

	results := checker.Analyze(pkgs, analyzers)

	type Key struct {
		Category string
		Root     string
	}
	type Value struct {
		Trace []string
		Count int
	}
	summary := make(map[Key]*Value)

	for _, r := range results {
		for _, d := range r.Diagnostics {
			entries := strings.Split(d.Message, "\t")
			root := ""
			if len(entries) > 0 {
				root = entries[len(entries)-1]
			}
			key := Key{Category: d.Category, Root: root}
			value := summary[key]
			if value == nil {
				value = &Value{Trace: entries, Count: 1}
			} else {
				value.Count++
				if len(value.Trace) > len(entries) {
					value.Trace = entries
				}
			}
			summary[key] = value
		}
	}
	if len(summary) == 0 {
		log.Println("no vulnerabilities found")
	}
	for key, value := range summary {
		fmt.Printf("%v\t%v\t(%v paths)\n\t%v\n", key.Category, key.Root, value.Count, strings.Join(value.Trace, "\n\t"))
	}
}

func jsonString(v any) string {
	s, _ := json.MarshalIndent(v, " ", " ")
	return string(s)
}

func dumpToFile(pkg2vulns map[string][]*osv.Entry) (fname string, err error) {
	vulnsFile, err := ioutil.TempFile("", "vuln")
	if err != nil {
		return "", fmt.Errorf("failed to create a temp file: %v", err)
	}
	defer func() {
		err2 := vulnsFile.Close()
		if err == nil && err2 != nil {
			fname, err = "", err2
		}
	}()

	if err := json.NewEncoder(vulnsFile).Encode(pkg2vulns); err != nil {
		return "", fmt.Errorf("failed to encode module vulnerability info: %v", err)
	}
	return vulnsFile.Name(), nil
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

	dbClient, err := client.NewClient(findGOVULNDB(cfg), client.Options{HTTPCache: govulncheck.DefaultCache()})
	if err != nil {
		exitf("failed to setup vulncheck client: %v", err)
	}
	modvulns, err := fetchOSVEntries(context.Background(), dbClient, pkgs)
	if err != nil {
		exitf("failed to fetch OSV entries: %v", err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(modvulns); err != nil {
		exitf("failed to encode module vulnerability info: %v", err)
	}
}

func goVersion() string {
	if v := os.Getenv("GOVERSION"); v != "" {
		// Unlikely to happen in practice, mostly used for testing.
		return v
	}
	out, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to determine go version; skipping stdlib scanning: %v\n", err)
		return ""
	}
	return string(bytes.TrimSpace(out))
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

// extractModules collects modules in `pkgs` up to uniqueness of
// module path and version.
func extractModules(pkgs []*packages.Package) []*packages.Module {
	modMap := map[string]*packages.Module{}

	stdlibModule.Version = goTagToSemver(goVersion())
	modMap[stdlibModule.Path] = stdlibModule

	seen := map[*packages.Package]bool{}
	var extract func(*packages.Package, map[string]*packages.Module)
	extract = func(pkg *packages.Package, modMap map[string]*packages.Module) {
		if pkg == nil || seen[pkg] {
			return
		}
		if pkg.Module != nil {
			if pkg.Module.Replace != nil {
				modMap[modKey(pkg.Module.Replace)] = pkg.Module
			} else {
				modMap[modKey(pkg.Module)] = pkg.Module
			}
		}
		seen[pkg] = true
		for _, imp := range pkg.Imports {
			extract(imp, modMap)
		}
	}
	for _, pkg := range pkgs {
		extract(pkg, modMap)
	}

	modules := []*packages.Module{}
	for _, mod := range modMap {
		modules = append(modules, mod)
	}
	return modules
}

// modKey creates a unique string identifier for mod.
func modKey(mod *packages.Module) string {
	if mod.Replace != nil {
		mod = mod.Replace
	}
	return fmt.Sprintf("%s@%s", mod.Path, mod.Version)
}
