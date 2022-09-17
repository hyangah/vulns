// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package database generates the vulnerability database.
package database

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hyangah/vulns/testutils/internal/derrors"
	"github.com/hyangah/vulns/testutils/internal/report"
	"github.com/hyangah/vulns/testutils/internal/stdlib"
	"golang.org/x/tools/txtar"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
)

const (
	dbURL = "https://pkg.go.dev/vuln/"

	// idDirectory is the name of the directory that contains entries
	// listed by their IDs.
	idDirectory = "ID"

	// yamlDir is the name of the directory in the vulndb repo that
	// contains reports.
	yamlDir = "data/reports"

	// versionFile is the name of the file in the vulndb repo that
	// tracks the generator version.
	versionFile = "data/version.md"

	// stdFileName is the name of the .json file in the vulndb repo
	// that will contain info on standard library vulnerabilities.
	stdFileName = "stdlib"

	// cmdModule is the name of the module containing Go toolchain
	// binaries.
	cmdModule = "cmd"

	// toolchainFileName is the name of the .json file in the vulndb repo
	// that will contain info on toolchain (cmd/...) vulnerabilities.
	toolchainFileName = "toolchain"
)

func Generate(ctx context.Context, data []byte, jsonDir string, indent bool) (err error) {
	defer derrors.Wrap(&err, "Generate")

	archive := txtar.Parse(data)

	jsonVulns, entries, err := generateEntries(ctx, archive)
	if err != nil {
		return err
	}

	index := make(client.DBIndex, len(jsonVulns))
	for modulePath, vulns := range jsonVulns {
		epath, err := client.EscapeModulePath(modulePath)
		if err != nil {
			return err
		}
		if err := writeVulns(filepath.Join(jsonDir, epath), vulns, indent); err != nil {
			return err
		}
		for _, v := range vulns {
			if v.Modified.After(index[modulePath]) {
				index[modulePath] = v.Modified
			}
		}
	}
	if err := writeJSON(filepath.Join(jsonDir, "index.json"), index, indent); err != nil {
		return err
	}
	if err := writeAliasIndex(jsonDir, entries, indent); err != nil {
		return err
	}
	return writeEntriesByID(filepath.Join(jsonDir, idDirectory), entries, indent)
}

func generateEntries(_ context.Context, archive *txtar.Archive) (map[string][]osv.Entry, []osv.Entry, error) {
	now := time.Now()
	jsonVulns := map[string][]osv.Entry{}
	var entries []osv.Entry
	for _, f := range archive.Files {
		if !strings.HasSuffix(f.Name, ".yaml") {
			continue
		}
		r, err := report.Read(bytes.NewReader(f.Data))
		if err != nil {
			return nil, nil, err
		}
		if r.Excluded != "" {
			// We may want to include excluded reports in the database
			// at some point, with a bit indicating that they are
			// uninteresting, but omit them for now.
			continue
		}

		if lints := r.Lint(f.Name); len(lints) > 0 {
			return nil, nil, fmt.Errorf("vuln.Lint: %v", lints)
		}

		name := strings.TrimSuffix(filepath.Base(f.Name), filepath.Ext(f.Name))
		linkName := fmt.Sprintf("%s%s", dbURL, name)
		entry, modulePaths := GenerateOSVEntry(name, linkName, now, *r)
		for _, modulePath := range modulePaths {
			jsonVulns[modulePath] = append(jsonVulns[modulePath], entry)
		}
		entries = append(entries, entry)
	}
	return jsonVulns, entries, nil
}

func writeVulns(outPath string, vulns []osv.Entry, indent bool) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %s", filepath.Dir(outPath), err)
	}
	return writeJSON(outPath+".json", vulns, indent)
}

func writeEntriesByID(idDir string, entries []osv.Entry, indent bool) error {
	// Write a directory containing entries by ID.
	if err := os.MkdirAll(idDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %v", idDir, err)
	}
	var idIndex []string
	for _, e := range entries {
		outPath := filepath.Join(idDir, e.ID+".json")
		if err := writeJSON(outPath, e, indent); err != nil {
			return err
		}
		idIndex = append(idIndex, e.ID)
	}
	// Write an index.json in the ID directory with a list of all the IDs.
	return writeJSON(filepath.Join(idDir, "index.json"), idIndex, indent)
}

// Write a JSON file containing a map from alias to GO IDs.
func writeAliasIndex(dir string, entries []osv.Entry, indent bool) error {
	aliasToGoIDs := map[string][]string{}
	for _, e := range entries {
		for _, a := range e.Aliases {
			aliasToGoIDs[a] = append(aliasToGoIDs[a], e.ID)
		}
	}
	return writeJSON(filepath.Join(dir, "aliases.json"), aliasToGoIDs, indent)
}

func writeJSON(filename string, value any, indent bool) (err error) {
	defer derrors.Wrap(&err, "writeJSON(%s)", filename)

	j, err := jsonMarshal(value, indent)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, j, 0644)
}

func jsonMarshal(v any, indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}

// GenerateOSVEntry create an osv.Entry for a report. In addition to the report, it
// takes the ID for the vuln and a URL that will point to the entry in the vuln DB.
// It returns the osv.Entry and a list of module paths that the vuln affects.
func GenerateOSVEntry(id, url string, lastModified time.Time, r report.Report) (osv.Entry, []string) {
	entry := osv.Entry{
		ID:        id,
		Published: r.Published,
		Modified:  lastModified,
		Withdrawn: r.Withdrawn,
		Details:   r.Description,
	}

	moduleMap := make(map[string]bool)
	for _, m := range r.Modules {
		switch m.Module {
		case stdlib.ModulePath:
			moduleMap[stdFileName] = true
		case cmdModule:
			moduleMap[toolchainFileName] = true
		default:
			moduleMap[m.Module] = true
		}
		entry.Affected = append(entry.Affected, generateAffected(m, url))
	}
	for _, ref := range r.References {
		entry.References = append(entry.References, osv.Reference{
			Type: string(ref.Type),
			URL:  ref.URL,
		})
	}
	entry.Aliases = r.GetAliases()

	var modulePaths []string
	for module := range moduleMap {
		modulePaths = append(modulePaths, module)
	}
	return entry, modulePaths
}

func generateAffectedRanges(versions []report.VersionRange) osv.Affects {
	a := osv.AffectsRange{Type: osv.TypeSemver}
	if len(versions) == 0 || versions[0].Introduced == "" {
		a.Events = append(a.Events, osv.RangeEvent{Introduced: "0"})
	}
	for _, v := range versions {
		if v.Introduced != "" {
			a.Events = append(a.Events, osv.RangeEvent{Introduced: v.Introduced.Canonical()})
		}
		if v.Fixed != "" {
			a.Events = append(a.Events, osv.RangeEvent{Fixed: v.Fixed.Canonical()})
		}
	}
	return osv.Affects{a}
}

func generateImports(m *report.Module) (imps []osv.EcosystemSpecificImport) {
	for _, p := range m.Packages {
		syms := append([]string{}, p.Symbols...)
		syms = append(syms, p.DerivedSymbols...)
		sort.Strings(syms)
		imps = append(imps, osv.EcosystemSpecificImport{
			Path:    p.Package,
			GOOS:    p.GOOS,
			GOARCH:  p.GOARCH,
			Symbols: syms,
		})
	}
	return imps
}

func generateAffected(m *report.Module, url string) osv.Affected {
	name := m.Module
	switch name {
	case stdlib.ModulePath:
		name = "stdlib"
	case cmdModule:
		name = "toolchain"
	}
	return osv.Affected{
		Package: osv.Package{
			Name:      name,
			Ecosystem: osv.GoEcosystem,
		},
		Ranges:           generateAffectedRanges(m.Versions),
		DatabaseSpecific: osv.DatabaseSpecific{URL: url},
		EcosystemSpecific: osv.EcosystemSpecific{
			Imports: generateImports(m),
		},
	}
}
