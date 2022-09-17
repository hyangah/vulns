// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hyangah/vulns/testutils/internal/stdlib"

	"golang.org/x/exp/slices"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

var pseudoVersionRE = regexp.MustCompile(`^v[0-9]+\.(0\.0-|\d+\.\d+-([^+]*\.)?0\.)\d{14}-[A-Za-z0-9]+(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// isPseudoVersion reports whether v is a pseudo-version.
// NOTE: this is taken from cmd/go/internal/modfetch/pseudo.go but
// uses regexp instead of the internal lazyregex package.
func isPseudoVersion(v string) bool {
	return strings.Count(v, "-") >= 2 && semver.IsValid(v) && pseudoVersionRE.MatchString(v)
}

func versionExists(version string, versions map[string]bool) (err error) {
	// TODO: for now, don't check validity of pseudo-versions.
	// We should add a check that the pseudo-version could feasibly exist given
	// the actual versions that we know about.
	//
	// The pseudo-version check should probably take into account the canonical
	// import path (investigate cmd/go/internal/modfetch/coderepo.go has, which
	// has something like this, check the error containing "has post-%v module
	// path").
	if isPseudoVersion(version) {
		return nil
	}
	if !versions[version] {
		return fmt.Errorf("proxy unaware of version")
	}
	return nil
}

func (m *Module) lintStdLib(addPkgIssue func(string)) {
	if len(m.Packages) == 0 {
		addPkgIssue("missing package")
	}
	for _, p := range m.Packages {
		if p.Package == "" {
			addPkgIssue("missing package")
		}
	}
}

func (m *Module) lintThirdParty(addPkgIssue func(string)) {
	if m.Module == "" {
		addPkgIssue("missing module")
		return
	}
	for _, p := range m.Packages {
		if p.Package == "" {
			addPkgIssue("missing package")
			continue
		}
		if !strings.HasPrefix(p.Package, m.Module) {
			addPkgIssue("module must be a prefix of package")
		}
		if err := module.CheckImportPath(p.Package); err != nil {
			addPkgIssue(err.Error())
		}
	}
}

func (m *Module) lintVersions(addPkgIssue func(string)) {
	if m.VulnerableAt != "" && !m.VulnerableAt.IsValid() {
		addPkgIssue(fmt.Sprintf("invalid vulnerable_at semantic version: %q", m.VulnerableAt))
	}
	for i, vr := range m.Versions {
		for _, v := range []Version{vr.Introduced, vr.Fixed} {
			if v != "" && !v.IsValid() {
				addPkgIssue(fmt.Sprintf("invalid semantic version: %q", v))
			}
		}
		if vr.Fixed != "" && !vr.Introduced.Before(vr.Fixed) {
			addPkgIssue(
				fmt.Sprintf("version %q >= %q", vr.Introduced, vr.Fixed))
			continue
		}
		// Check all previous version ranges to ensure none overlap with
		// this one.
		for _, vrPrev := range m.Versions[:i] {
			if vrPrev.Introduced.Before(vr.Fixed) && vr.Introduced.Before(vrPrev.Fixed) {
				addPkgIssue(fmt.Sprintf("version ranges overlap: [%v,%v), [%v,%v)", vr.Introduced, vr.Fixed, vr.Introduced, vrPrev.Fixed))
			}
		}
	}
}

var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func (r *Report) lintCVEs(addIssue func(string)) {
	if len(r.CVEs) > 0 && r.CVEMetadata != nil && r.CVEMetadata.ID != "" {
		// TODO: consider removing one of these fields from the Report struct.
		addIssue("only one of cve and cve_metadata.id should be present")
	}

	for _, cve := range r.CVEs {
		if !cveRegex.MatchString(cve) {
			addIssue("malformed cve identifier")
		}
	}

	if r.CVEMetadata != nil {
		if r.CVEMetadata.ID == "" {
			addIssue("cve_metadata.id is required")
		} else if !cveRegex.MatchString(r.CVEMetadata.ID) {
			addIssue("malformed cve_metadata.id identifier")
		}
	}
}

func (r *Report) lintLineLength(field, content string, addIssue func(string)) {
	const maxLineLength = 100
	for _, line := range strings.Split(content, "\n") {
		if len(line) <= maxLineLength {
			continue
		}
		if !strings.Contains(content, " ") {
			continue // A single long word is OK.
		}
		addIssue(fmt.Sprintf("%v contains line > %v characters long", field, maxLineLength))
		return
	}
}

// Regex patterns for standard library links.
var (
	prRegex       = regexp.MustCompile(`https://go.dev/cl/\d+`)
	commitRegex   = regexp.MustCompile(`https://go.googlesource.com/[^/]+/\+/([^/]+)`)
	issueRegex    = regexp.MustCompile(`https://go.dev/issue/\d+`)
	announceRegex = regexp.MustCompile(`https://groups.google.com/g/golang-(announce|dev|nuts)/c/([^/]+)`)
)

// Checks that the "links" section of a Report for a package in the
// standard library contains all necessary links, and no third-party links.
func (r *Report) lintStdLibLinks(addIssue func(string)) {
	var (
		hasFixLink      = false
		hasReportLink   = false
		hasAnnounceLink = false
	)
	for _, ref := range r.References {
		switch ref.Type {
		case ReferenceTypeAdvisory:
			addIssue(fmt.Sprintf("%q: advisory reference should not be set for first-party issues", ref.URL))
		case ReferenceTypeFix:
			hasFixLink = true
			if !prRegex.MatchString(ref.URL) && !commitRegex.MatchString(ref.URL) {
				addIssue(fmt.Sprintf("%q: fix reference should match %q or %q", ref.URL, prRegex, commitRegex))
			}
		case ReferenceTypeReport:
			hasReportLink = true
			if !issueRegex.MatchString(ref.URL) {
				addIssue(fmt.Sprintf("%q: report reference should match %q", ref.URL, issueRegex))
			}
		case ReferenceTypeWeb:
			if !announceRegex.MatchString(ref.URL) {
				addIssue(fmt.Sprintf("%q: web references should only contain announcement links matching %q", ref.URL, announceRegex))
			} else {
				hasAnnounceLink = true
			}
		}
	}
	if !hasFixLink {
		addIssue("references should contain at least one fix")
	}
	if !hasReportLink {
		addIssue("references should contain at least one report")
	}
	if !hasAnnounceLink {
		addIssue(fmt.Sprintf("references should contain an announcement link matching %q", announceRegex))
	}
}

func (r *Report) lintLinks(addIssue func(string)) {
	for _, ref := range r.References {
		if !slices.Contains(ReferenceTypes, ref.Type) {
			addIssue(fmt.Sprintf("%q is not a valid reference type", ref.Type))
		}
		l := ref.URL
		if _, err := url.ParseRequestURI(l); err != nil {
			addIssue(fmt.Sprintf("%q is not a valid URL", l))
		}
		if fixed := fixURL(l); fixed != l {
			addIssue(fmt.Sprintf("unfixed url: %q should be %q", l, fixURL(l)))
		}
	}
}

// Lint checks the content of a Report and outputs a list of strings
// representing lint errors.
// TODO: It might make sense to include warnings or informational things
// alongside errors, especially during for use during the triage process.
func (r *Report) Lint(filename string) []string {
	var issues []string

	addIssue := func(iss string) {
		issues = append(issues, iss)
	}

	switch filepath.Base(filepath.Dir(filename)) {
	case "reports":
		if r.Excluded != "" {
			addIssue("report in reports/ must not have excluded set")
		}
		if len(r.Modules) == 0 {
			addIssue("no modules")
		}
		if r.Description == "" {
			addIssue("missing description")
		}
	case "excluded":
		if r.Excluded == "" {
			addIssue("report in excluded/ must have excluded set")
		} else if !slices.Contains(ExcludedReasons, r.Excluded) {
			addIssue(fmt.Sprintf("excluded (%q) is not in set %v", r.Excluded, ExcludedReasons))
		}
		if len(r.Modules) != 0 {
			addIssue("excluded report should not have modules")
		}
		if len(r.CVEs) == 0 && len(r.GHSAs) == 0 {
			addIssue("excluded report must have at least one associated CVE or GHSA")
		}
	}

	isStdLibReport := false
	for i, m := range r.Modules {
		addPkgIssue := func(iss string) {
			addIssue(fmt.Sprintf("modules[%v]: %v", i, iss))
		}

		if m.Module == stdlib.ModulePath || m.Module == "cmd" {
			isStdLibReport = true
			m.lintStdLib(addPkgIssue)
		} else {
			m.lintThirdParty(addPkgIssue)
		}
		for _, p := range m.Packages {
			if strings.HasPrefix(p.Package, "cmd/") && m.Module != "cmd" {
				addPkgIssue(fmt.Sprintf(`%q should be in module "cmd", not %q`, p.Package, m.Module))
			}
		}

		m.lintVersions(addPkgIssue)
	}

	r.lintLineLength("description", r.Description, addIssue)
	if r.CVEMetadata != nil {
		r.lintLineLength("cve_metadata.description", r.CVEMetadata.Description, addIssue)
	}
	r.lintCVEs(addIssue)

	r.lintLinks(addIssue)
	if isStdLibReport {
		r.lintStdLibLinks(addIssue)
	}

	return issues
}

var commitHashRegex = regexp.MustCompile(`^[a-f0-9]+$`)

func (r *Report) Fix() {
	for _, ref := range r.References {
		ref.URL = fixURL(ref.URL)
	}
	fixVersion := func(mod string, vp *Version) {
		v := *vp
		if v == "" {
			return
		}
		v = Version(strings.TrimPrefix(string(v), "v"))
		v = Version(strings.TrimPrefix(string(v), "go"))
		if v.IsValid() {
			build := semver.Build(v.V())
			v = Version(v.Canonical())
			if build != "" {
				v += Version(build)
			}
		}
		*vp = v
	}
	for _, m := range r.Modules {
		for i := range m.Versions {
			fixVersion(m.Module, &m.Versions[i].Introduced)
			fixVersion(m.Module, &m.Versions[i].Fixed)
		}
		fixVersion(m.Module, &m.VulnerableAt)
	}
}

var urlReplacements = []struct {
	re   *regexp.Regexp
	repl string
}{{
	regexp.MustCompile(`golang.org`),
	`go.dev`,
}, {
	regexp.MustCompile(`https?://groups.google.com/forum/\#\![^/]*/([^/]+)/([^/]+)/(.*)`),

	`https://groups.google.com/g/$1/c/$2/m/$3`,
}, {
	regexp.MustCompile(`.*github.com/golang/go/issues`),
	`https://go.dev/issue`,
}, {
	regexp.MustCompile(`.*github.com/golang/go/commit`),
	`https://go.googlesource.com/+`,
},
}

func fixURL(u string) string {
	for _, repl := range urlReplacements {
		u = repl.re.ReplaceAllString(u, repl.repl)
	}
	return u
}
