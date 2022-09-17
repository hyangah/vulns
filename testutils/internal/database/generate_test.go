// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/osv"
	"github.com/hyangah/vulns/testutils/internal/report"
)

func TestGenerate(t *testing.T) {
	r := report.Report{
		Modules: []*report.Module{
			{
				Module: "example.com/vulnerable/v2",
				Versions: []report.VersionRange{
					{Fixed: "2.1.1"},
					{Introduced: "2.3.4", Fixed: "2.3.5"},
					{Introduced: "2.5.0"},
				},
				Packages: []*report.Package{
					{
						Package:        "example.com/vulnerable/v2",
						GOOS:           []string{"windows"},
						GOARCH:         []string{"arm64"},
						Symbols:        []string{"A", "B.b"},
						DerivedSymbols: []string{"D"},
					},
				},
			}, {
				Module: "vanity.host/vulnerable",
				Versions: []report.VersionRange{
					{Fixed: "2.1.1"},
					{Introduced: "2.3.4", Fixed: "2.3.5"},
					{Introduced: "2.5.0"},
				},
				Packages: []*report.Package{
					{
						Package: "vanity.host/vulnerable/package",
						GOOS:    []string{"windows"},
						GOARCH:  []string{"arm64"},
						Symbols: []string{"A.b", "b"},
					},
				},
			}, {
				Module: "example.com/also-vulnerable",
				Versions: []report.VersionRange{
					{Fixed: "2.1.1"},
				},
				Packages: []*report.Package{
					{
						Package: "example.com/also-vulnerable/package",
						GOOS:    []string{"windows"},
						GOARCH:  []string{"arm64"},
						Symbols: []string{"z"},
					},
				},
			},
		},
		Description: "It's a real bad one, I'll tell you that",
		CVEs:        []string{"CVE-0000-0000"},
		GHSAs:       []string{"GHSA-abcd-efgh"},
		Credit:      "ignored",
		References: []*report.Reference{
			{Type: report.ReferenceTypeAdvisory, URL: "advisory"},
			{Type: report.ReferenceTypeReport, URL: "issue"},
			{Type: report.ReferenceTypeFix, URL: "fix"},
			{Type: report.ReferenceTypeWeb, URL: "web"},
		},
	}

	url := "https://vulns.golang.org/GO-1991-0001.html"
	wantEntry := osv.Entry{
		ID:      "GO-1991-0001",
		Details: "It's a real bad one, I'll tell you that",
		References: []osv.Reference{
			{Type: "ADVISORY", URL: "advisory"},
			{Type: "REPORT", URL: "issue"},
			{Type: "FIX", URL: "fix"},
			{Type: "WEB", URL: "web"},
		},
		Aliases: []string{"CVE-0000-0000", "GHSA-abcd-efgh"},
		Affected: []osv.Affected{
			{
				Package: osv.Package{
					Name:      "example.com/vulnerable/v2",
					Ecosystem: "Go",
				},
				Ranges: []osv.AffectsRange{
					{
						Type: osv.TypeSemver,
						Events: []osv.RangeEvent{
							{
								Introduced: "0",
							},
							{
								Fixed: "2.1.1",
							},
							{
								Introduced: "2.3.4",
							},
							{
								Fixed: "2.3.5",
							},
							{
								Introduced: "2.5.0",
							},
						},
					},
				},
				DatabaseSpecific: osv.DatabaseSpecific{URL: url},
				EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{
						{
							Path:    "example.com/vulnerable/v2",
							GOOS:    []string{"windows"},
							GOARCH:  []string{"arm64"},
							Symbols: []string{"A", "B.b", "D"},
						},
					},
				},
			},
			{
				Package: osv.Package{
					Name:      "vanity.host/vulnerable",
					Ecosystem: "Go",
				},
				Ranges: []osv.AffectsRange{
					{
						Type: osv.TypeSemver,
						Events: []osv.RangeEvent{
							{
								Introduced: "0",
							},
							{
								Fixed: "2.1.1",
							},
							{
								Introduced: "2.3.4",
							},
							{
								Fixed: "2.3.5",
							},
							{
								Introduced: "2.5.0",
							},
						},
					},
				},
				DatabaseSpecific: osv.DatabaseSpecific{URL: url},
				EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{
						{
							Path:    "vanity.host/vulnerable/package",
							GOOS:    []string{"windows"},
							GOARCH:  []string{"arm64"},
							Symbols: []string{"A.b", "b"},
						},
					},
				},
			},
			{
				Package: osv.Package{
					Name:      "example.com/also-vulnerable",
					Ecosystem: "Go",
				},
				Ranges: []osv.AffectsRange{
					{
						Type: osv.TypeSemver,
						Events: []osv.RangeEvent{
							{
								Introduced: "0",
							},
							{
								Fixed: "2.1.1",
							},
						},
					},
				},
				DatabaseSpecific: osv.DatabaseSpecific{URL: url},
				EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{
						{
							Path:    "example.com/also-vulnerable/package",
							GOOS:    []string{"windows"},
							GOARCH:  []string{"arm64"},
							Symbols: []string{"z"},
						},
					},
				},
			},
		},
	}
	wantModules := []string{"example.com/vulnerable/v2", "vanity.host/vulnerable", "example.com/also-vulnerable"}
	sort.Strings(wantModules)

	gotEntry, gotModules := GenerateOSVEntry("GO-1991-0001", url, time.Time{}, r)
	if diff := cmp.Diff(wantEntry, gotEntry, cmp.Comparer(func(a, b time.Time) bool { return a.Equal(b) })); diff != "" {
		t.Errorf("Generate returned unexpected entry (-want +got):\n%s", diff)
	}
	sort.Strings(gotModules)
	if !reflect.DeepEqual(gotModules, wantModules) {
		t.Errorf("Generate returned unexpected modules: got %v, want %v", gotModules, wantModules)
	}
}

func TestSemverCanonicalize(t *testing.T) {
	in := []report.VersionRange{
		{
			Introduced: "1.16.0",
			Fixed:      "1.17.0",
		},
	}
	expected := osv.Affects{
		{
			Type: osv.TypeSemver,
			Events: []osv.RangeEvent{
				{
					Introduced: "1.16.0",
				},
				{
					Fixed: "1.17.0",
				},
			},
		},
	}

	out := generateAffectedRanges(in)
	if !reflect.DeepEqual(out, expected) {
		t.Fatalf("unexpected output: got %#v, want %#v", out, expected)
	}
}
