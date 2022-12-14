// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package osvutil

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/mod/module"
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

// GoTagToSemver replaces go version to semver style version string.
// This is a modified copy of pkgsite/internal/stdlib:VersionForTag.
func GoTagToSemver(tag string) string {
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

func FetchOSVEntries(ctx context.Context, cli client.Client, pkgs []*packages.Package) (map[string][]*osv.Entry, error) {
	// fetch osv entries, and organize based on the module.
	modules := extractModules(pkgs)
	stdlibModule := &packages.Module{
		Path:    "stdlib",
		Version: GoTagToSemver(goVersion()),
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
		// If module path is not a valid, exportable module path (e.g. contains dot!)
		// we don't need to lookup module.
		if err := module.CheckPath(modPath); err != nil {
			continue
		}
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
				for _, p := range a.EcosystemSpecific.Imports {
					if p.Path == pkg.PkgPath {
						vulns = append(vulns, v)
					}
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
			if modVersion == "" {
				// Module version of "" means the module version is not available,
				// and so we don't want to spam users with potential false alarms.
				// TODO: issue warning for "" cases above?
				continue
			}
			if !a.Ranges.AffectsSemver(modVersion) {
				continue
			}
			var filteredImports []osv.EcosystemSpecificImport
			for _, p := range a.EcosystemSpecific.Imports {
				if matchesPlatform(goos, goarch, p) {
					filteredImports = append(filteredImports, p)
				}
			}
			if len(a.EcosystemSpecific.Imports) != 0 && len(filteredImports) == 0 {
				continue
			}
			a.EcosystemSpecific.Imports = filteredImports
			filteredAffected = append(filteredAffected, a)
		}

		if len(filteredAffected) == 0 {
			continue
		}
		// save the non-empty vulnerability with only
		// affected symbols.
		newV := *v
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

func matchesPlatform(os, arch string, e osv.EcosystemSpecificImport) bool {
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

func normalizeOSVEntries(_ *packages.Module, vulns []*osv.Entry) []*osv.Entry {
	for _, v := range vulns {
		// osv entry's details has many arbitrarilily place new line breaks. Remove them.
		// TODO(hyangah): file an issue to vulnDB?
		v.Details = strings.TrimSpace(strings.Replace(v.Details, "\n", " ", -1))
	}
	return vulns
}

func FindGOVULNDB(cfg *packages.Config) []string {
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

// modKey creates a unique string identifier for mod.
func modKey(mod *packages.Module) string {
	if mod.Replace != nil {
		mod = mod.Replace
	}
	return fmt.Sprintf("%s@%s", mod.Path, mod.Version)
}

// extractModules collects modules in `pkgs` up to uniqueness of
// module path and version.
func extractModules(pkgs []*packages.Package) []*packages.Module {
	modMap := map[string]*packages.Module{}

	stdlibModule.Version = GoTagToSemver(goVersion())
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
