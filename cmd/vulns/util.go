// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package main

import (
	"context"
	"os"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
)

var stdlibModule = &packages.Module{
	Path: "stdlib",
}

var (
	// Regexp for matching go tags. The groups are:
	// 1  the major.minor version
	// 2  the patch version, or empty if none
	// 3  the entire prerelease, if present
	// 4  the prerelease type ("beta" or "rc")
	// 5  the prerelease number
	tagRegexp = regexp.MustCompile(`^go(\d+\.\d+)(\.\d+|)((beta|rc|-pre)(\d+))?$`)
)

// This is a modified copy of pkgsite/internal/stdlib:VersionForTag.
func goTagToSemver(tag string) string {
	if tag == "" {
		return ""
	}

	tag = strings.Fields(tag)[0]
	// Special cases for go1.
	if tag == "go1" {
		return "v1.0.0"
	}
	if tag == "go1.0" {
		return ""
	}
	m := tagRegexp.FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	version := "v" + m[1]
	if m[2] != "" {
		version += m[2]
	} else {
		version += ".0"
	}
	if m[3] != "" {
		if !strings.HasPrefix(m[4], "-") {
			version += "-"
		}
		version += m[4] + "." + m[5]
	}
	return version
}

func walk(pkgs []*packages.Package, fn func(pkg *packages.Package) error) error {
	seen := map[*packages.Package]bool{}
	var visit func(*packages.Package) error
	visit = func(pkg *packages.Package) error {
		if pkg == nil || seen[pkg] {
			return nil
		}
		if err := fn(pkg); err != nil {
			return err
		}

		seen[pkg] = true
		for _, imp := range pkg.Imports {
			if err := visit(imp); err != nil {
				return err
			}
		}
		return nil
	}
	for _, pkg := range pkgs {
		if err := visit(pkg); err != nil {
			return err
		}
	}
	return nil
}

func fetchOSVEntries(ctx context.Context, cli client.Client, pkgs []*packages.Package) (map[string][]*osv.Entry, error) {
	// fetch osv entries, and organize based on the module.
	modules := extractModules(pkgs)
	stdlibModule := &packages.Module{
		Path:    "stdlib",
		Version: goTagToSemver(goVersion()),
	}
	modules = append(modules, stdlibModule)

	mod2OSV := make(map[string][]*osv.Entry)
	// TODO(hyangah): run multiple cli.GetByModule calls in parallel
	// unless batch API can be offered from upstream.
	for _, mod := range modules {
		m := effectiveModule(mod)
		if m == nil {
			continue
		}
		modPath := m.Path
		vulns, err := cli.GetByModule(ctx, modPath)
		if err != nil {
			return nil, err
		}
		vulns = normalizeOSVEntries(m, filterOSVEntries(m, vulns))
		if len(vulns) > 0 {
			mod2OSV[modKey(mod)] = vulns
		}
	}
	pkg2OSV := make(map[string][]*osv.Entry)
	walk(pkgs, func(pkg *packages.Package) error {
		m := pkg.Module
		if m == nil && isStdPackage(pkg.PkgPath) {
			m = stdlibModule
		}
		var vulns []*osv.Entry
		for _, v := range mod2OSV[modKey(m)] {
			for _, a := range v.Affected {
				if a.Package.Name == pkg.PkgPath {
					vulns = append(vulns, v)
					break
				}
			}
		}
		if len(vulns) > 0 {
			pkg2OSV[pkg.PkgPath] = vulns
		} else {
		}
		return nil
	})
	return pkg2OSV, nil
}

func effectiveModule(mod *packages.Module) *packages.Module {
	m := mod
	for ; m != nil; m = m.Replace {
		if m.Replace == nil {
			return m
		}
	}
	return m
}

func filterOSVEntries(module *packages.Module, vulns []*osv.Entry) []*osv.Entry {
	goos, goarch := lookupEnv("GOOS", runtime.GOOS), lookupEnv("GOARCH", runtime.GOARCH)
	// TODO: add OS/Arch check - see the use of matchesPlatform
	// https://github.com/golang/vuln/blob/4bd4888cc0609c2fdddc1eb4e66fa070397d921e/vulncheck/vulncheck.go#L299
	modVersion := module.Version
	if module.Replace != nil {
		modVersion = module.Replace.Version
	}
	// TODO(https://golang.org/issues/49264): if modVersion == "", try vcs?
	var filteredVulns []*osv.Entry
	for _, v := range vulns {
		var filteredAffected []osv.Affected
		// leave only the entries that correspond to the module.
		for _, a := range v.Affected {
			if a.Package.Ecosystem != osv.GoEcosystem {
				continue
			}
			if module.Path == "stdlib" && !isStdPackage(a.Package.Name) {
				continue
			}
			if module.Path != "stdlib" && !strings.HasPrefix(a.Package.Name, module.Path) {
				continue
			}
			// A module version is affected if
			//  - it is included in one of the affected version ranges
			//  - and module version is not ""
			//  The latter means the module version is not available, so
			//  we don't want to spam users with potential false alarms.
			//  TODO: issue warning for "" cases above?
			affected := modVersion != "" && a.Ranges.AffectsSemver(modVersion) && matchesPlatform(goos, goarch, a.EcosystemSpecific)
			if affected {
				filteredAffected = append(filteredAffected, a)
			}
		}
		if len(filteredAffected) == 0 {
			continue
		}
		// save the non-empty vulnerability with only
		// affected symbols.
		newV := *v // narrow copy
		newV.Affected = filteredAffected
		filteredVulns = append(filteredVulns, &newV)
	}
	return filteredVulns
}

func lookupEnv(key, defaultValue string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return defaultValue
}

func matchesPlatform(os, arch string, e osv.EcosystemSpecific) bool {
	matchesOS := len(e.GOOS) == 0
	matchesArch := len(e.GOARCH) == 0
	for _, o := range e.GOOS {
		if os == o {
			matchesOS = true
			break
		}
	}
	for _, a := range e.GOARCH {
		if arch == a {
			matchesArch = true
			break
		}
	}
	return matchesOS && matchesArch
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

func normalizeOSVEntries(mod *packages.Module, vulns []*osv.Entry) []*osv.Entry {
	for _, v := range vulns {
		// osv entry's details has many arbitrarilily place new line breaks. Remove them.
		// TODO(hyangah): file an issue to vulnDB?
		v.Details = strings.TrimSpace(strings.Replace(v.Details, "\n", " ", -1))
	}
	return vulns
}

func findGOVULNDB(cfg *packages.Config) []string {
	for _, kv := range cfg.Env {
		if strings.HasPrefix(kv, "GOVULNDB=") {
			return strings.Split(kv[len("GOVULNDB="):], ",")
		}
	}
	if GOVULNDB := os.Getenv("GOVULNDB"); GOVULNDB != "" {
		return strings.Split(GOVULNDB, ",")
	}
	return []string{"https://vuln.go.dev"}
}
