// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package analysis

import (
	"fmt"
	"go/token"
	"go/types"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/scanner"

	"github.com/hyangah/vulns/internal/checker"
	"github.com/hyangah/vulns/internal/testenv"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
)

// --------

// This is a partial copy of go/analysis/analysistest:
// Since we vendored go/analysis to access go/analysis/internal/checker
// this analyzer cannot work with the official analyzer test
// api without copying the entire x/tools.

type Testing interface {
	Errorf(format string, args ...interface{})
}

// Run applies an analysis to the packages denoted by the "go list" patterns.
//
// It loads the packages from the specified GOPATH-style project
// directory using golang.org/x/tools/go/packages, runs the analysis on
// them, and checks that each analysis emits the expected diagnostics
// and facts specified by the contents of '// want ...' comments in the
// package's source files. It treats a comment of the form
// "//...// want..." or "/*...// want... */" as if it starts at 'want'
//
// An expectation of a Diagnostic is specified by a string literal
// containing a regular expression that must match the diagnostic
// message. For example:
//
//	fmt.Printf("%s", 1) // want `cannot provide int 1 to %s`
//
// An expectation of a Fact associated with an object is specified by
// 'name:"pattern"', where name is the name of the object, which must be
// declared on the same line as the comment, and pattern is a regular
// expression that must match the string representation of the fact,
// fmt.Sprint(fact). For example:
//
//	func panicf(format string, args interface{}) { // want panicf:"printfWrapper"
//
// Package facts are specified by the name "package" and appear on
// line 1 of the first source file of the package.
//
// A single 'want' comment may contain a mixture of diagnostic and fact
// expectations, including multiple facts about the same object:
//
//	// want "diag" "diag2" x:"fact1" x:"fact2" y:"fact3"
//
// Unexpected diagnostics and facts, and unmatched expectations, are
// reported as errors to the Testing.
//
// Run reports an error to the Testing if loading or analysis failed.
// Run also returns a Result for each package for which analysis was
// attempted, even if unsuccessful. It is safe for a test to ignore all
// the results, but a test may use it to perform additional checks.
func Run(t Testing, dir string, a *analysis.Analyzer, patterns ...string) []*Result {
	if t, ok := t.(testenv.Testing); ok {
		testenv.NeedsGoPackages(t)
	}

	pkgs, err := loadPackages(a, dir, patterns...)
	if err != nil {
		t.Errorf("loading %s: %v", patterns, err)
		return nil
	}
	// ASK(adonovan): if checker package that accepts []*packages.Package is published
	// we may consider exporting part of analysistest api.
	return RunWithPackages(t, dir, a, pkgs)
}

// RunWithPackages is like Run, but works with pre-loaded packages.
func RunWithPackages(t Testing, dir string, a *analysis.Analyzer, pkgs []*packages.Package) []*Result {
	results := checker.TestAnalyzer(a, pkgs)
	for _, result := range results {
		if result.Err != nil {
			t.Errorf("error analyzing %s: %v", result.Pass, result.Err)
		} else {
			check(t, dir, result.Pass, result.Diagnostics, result.Facts)
		}
	}
	return results
}

// A Result holds the result of applying an analyzer to a package.

// A Result holds the result of applying an analyzer to a package.
type Result = checker.TestAnalyzerResult

// loadPackages uses go/packages to load a specified packages (from source, with
// dependencies) from dir, which is the root of a GOPATH-style project
// tree. It returns an error if any package had an error, or the pattern
// matched no packages.
func loadPackages(a *analysis.Analyzer, dir string, patterns ...string) ([]*packages.Package, error) {
	// packages.Load loads the real standard library, not a minimal
	// fake version, which would be more efficient, especially if we
	// have many small tests that import, say, net/http.
	// However there is no easy way to make go/packages to consume
	// a list of packages we generate and then do the parsing and
	// typechecking, though this feature seems to be a recurring need.

	// ASK(adonovan): This is modified from the go/analysis/analysistest
	// in order to add packages.NeedModule.
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports |
		packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo |
		packages.NeedDeps | packages.NeedModule
	cfg := &packages.Config{
		Mode:  mode,
		Dir:   dir,
		Tests: true,
		Env:   append(os.Environ(), "GOPATH="+dir, "GO111MODULE=off", "GOPROXY=off"),
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}

	// Do NOT print errors if the analyzer will continue running.
	// It is incredibly confusing for tests to be printing to stderr
	// willy-nilly instead of their test logs, especially when the
	// errors are expected and are going to be fixed.
	if !a.RunDespiteErrors {
		packages.PrintErrors(pkgs)
	}

	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages matched %s", patterns)
	}
	return pkgs, nil
}

// check inspects an analysis pass on which the analysis has already
// been run, and verifies that all reported diagnostics and facts match
// specified by the contents of "// want ..." comments in the package's
// source files, which must have been parsed with comments enabled.
func check(t Testing, gopath string, pass *analysis.Pass, diagnostics []analysis.Diagnostic, facts map[types.Object][]analysis.Fact) {
	type key struct {
		file string
		line int
	}

	want := make(map[key][]expectation)

	// processComment parses expectations out of comments.
	processComment := func(filename string, linenum int, text string) {
		text = strings.TrimSpace(text)

		// Any comment starting with "want" is treated
		// as an expectation, even without following whitespace.
		if rest := strings.TrimPrefix(text, "want"); rest != text {
			lineDelta, expects, err := parseExpectations(rest)
			if err != nil {
				t.Errorf("%s:%d: in 'want' comment: %s", filename, linenum, err)
				return
			}
			if expects != nil {
				want[key{filename, linenum + lineDelta}] = expects
			}
		}
	}

	// Extract 'want' comments from parsed Go files.
	for _, f := range pass.Files {
		for _, cgroup := range f.Comments {
			for _, c := range cgroup.List {

				text := strings.TrimPrefix(c.Text, "//")
				if text == c.Text { // not a //-comment.
					text = strings.TrimPrefix(text, "/*")
					text = strings.TrimSuffix(text, "*/")
				}

				// Hack: treat a comment of the form "//...// want..."
				// or "/*...// want... */
				// as if it starts at 'want'.
				// This allows us to add comments on comments,
				// as required when testing the buildtag analyzer.
				if i := strings.Index(text, "// want"); i >= 0 {
					text = text[i+len("// "):]
				}

				// It's tempting to compute the filename
				// once outside the loop, but it's
				// incorrect because it can change due
				// to //line directives.
				posn := pass.Fset.Position(c.Pos())
				filename := sanitize(gopath, posn.Filename)
				processComment(filename, posn.Line, text)
			}
		}
	}

	// Extract 'want' comments from non-Go files.
	// TODO(adonovan): we may need to handle //line directives.
	for _, filename := range pass.OtherFiles {
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			t.Errorf("can't read '// want' comments from %s: %v", filename, err)
			continue
		}
		filename := sanitize(gopath, filename)
		linenum := 0
		for _, line := range strings.Split(string(data), "\n") {
			linenum++

			// Hack: treat a comment of the form "//...// want..."
			// or "/*...// want... */
			// as if it starts at 'want'.
			// This allows us to add comments on comments,
			// as required when testing the buildtag analyzer.
			if i := strings.Index(line, "// want"); i >= 0 {
				line = line[i:]
			}

			if i := strings.Index(line, "//"); i >= 0 {
				line = line[i+len("//"):]
				processComment(filename, linenum, line)
			}
		}
	}

	checkMessage := func(posn token.Position, kind, name, message string) {
		posn.Filename = sanitize(gopath, posn.Filename)
		k := key{posn.Filename, posn.Line}
		expects := want[k]
		var unmatched []string
		for i, exp := range expects {
			if exp.kind == kind && exp.name == name {
				if exp.rx.MatchString(message) {
					// matched: remove the expectation.
					expects[i] = expects[len(expects)-1]
					expects = expects[:len(expects)-1]
					want[k] = expects
					return
				}
				unmatched = append(unmatched, fmt.Sprintf("%#q", exp.rx))
			}
		}
		if unmatched == nil {
			t.Errorf("%v: unexpected %s: %v", posn, kind, message)
		} else {
			t.Errorf("%v: %s %q does not match pattern %s",
				posn, kind, message, strings.Join(unmatched, " or "))
		}
	}

	// Check the diagnostics match expectations.
	for _, f := range diagnostics {
		// TODO(matloob): Support ranges in analysistest.
		posn := pass.Fset.Position(f.Pos)
		checkMessage(posn, "diagnostic", "", f.Message)
	}

	// Check the facts match expectations.
	// Report errors in lexical order for determinism.
	// (It's only deterministic within each file, not across files,
	// because go/packages does not guarantee file.Pos is ascending
	// across the files of a single compilation unit.)
	var objects []types.Object
	for obj := range facts {
		objects = append(objects, obj)
	}
	sort.Slice(objects, func(i, j int) bool {
		// Package facts compare less than object facts.
		ip, jp := objects[i] == nil, objects[j] == nil // whether i, j is a package fact
		if ip != jp {
			return ip && !jp
		}
		return objects[i].Pos() < objects[j].Pos()
	})
	for _, obj := range objects {
		var posn token.Position
		var name string
		if obj != nil {
			// Object facts are reported on the declaring line.
			name = obj.Name()
			posn = pass.Fset.Position(obj.Pos())
		} else {
			// Package facts are reported at the start of the file.
			name = "package"
			posn = pass.Fset.Position(pass.Files[0].Pos())
			posn.Line = 1
		}

		for _, fact := range facts[obj] {
			checkMessage(posn, "fact", name, fmt.Sprint(fact))
		}
	}

	// Reject surplus expectations.
	//
	// Sometimes an Analyzer reports two similar diagnostics on a
	// line with only one expectation. The reader may be confused by
	// the error message.
	// TODO(adonovan): print a better error:
	// "got 2 diagnostics here; each one needs its own expectation".
	var surplus []string
	for key, expects := range want {
		for _, exp := range expects {
			err := fmt.Sprintf("%s:%d: no %s was reported matching %#q", key.file, key.line, exp.kind, exp.rx)
			surplus = append(surplus, err)
		}
	}
	sort.Strings(surplus)
	for _, err := range surplus {
		t.Errorf("%s", err)
	}
}

type expectation struct {
	kind string // either "fact" or "diagnostic"
	name string // name of object to which fact belongs, or "package" ("fact" only)
	rx   *regexp.Regexp
}

func (ex expectation) String() string {
	return fmt.Sprintf("%s %s:%q", ex.kind, ex.name, ex.rx) // for debugging
}

// parseExpectations parses the content of a "// want ..." comment
// and returns the expectations, a mixture of diagnostics ("rx") and
// facts (name:"rx").
func parseExpectations(text string) (lineDelta int, expects []expectation, err error) {
	var scanErr string
	sc := new(scanner.Scanner).Init(strings.NewReader(text))
	sc.Error = func(_ *scanner.Scanner, msg string) {
		scanErr = msg // e.g. bad string escape
	}
	sc.Mode = scanner.ScanIdents | scanner.ScanStrings | scanner.ScanRawStrings | scanner.ScanInts

	scanRegexp := func(tok rune) (*regexp.Regexp, error) {
		if tok != scanner.String && tok != scanner.RawString {
			return nil, fmt.Errorf("got %s, want regular expression",
				scanner.TokenString(tok))
		}
		pattern, _ := strconv.Unquote(sc.TokenText()) // can't fail
		return regexp.Compile(pattern)
	}

	for {
		tok := sc.Scan()
		switch tok {
		case '+':
			tok = sc.Scan()
			if tok != scanner.Int {
				return 0, nil, fmt.Errorf("got +%s, want +Int", scanner.TokenString(tok))
			}
			lineDelta, _ = strconv.Atoi(sc.TokenText())
		case scanner.String, scanner.RawString:
			rx, err := scanRegexp(tok)
			if err != nil {
				return 0, nil, err
			}
			expects = append(expects, expectation{"diagnostic", "", rx})

		case scanner.Ident:
			name := sc.TokenText()
			tok = sc.Scan()
			if tok != ':' {
				return 0, nil, fmt.Errorf("got %s after %s, want ':'",
					scanner.TokenString(tok), name)
			}
			tok = sc.Scan()
			rx, err := scanRegexp(tok)
			if err != nil {
				return 0, nil, err
			}
			expects = append(expects, expectation{"fact", name, rx})

		case scanner.EOF:
			if scanErr != "" {
				return 0, nil, fmt.Errorf("%s", scanErr)
			}
			return lineDelta, expects, nil

		default:
			return 0, nil, fmt.Errorf("unexpected %s", scanner.TokenString(tok))
		}
	}
}

// sanitize removes the GOPATH portion of the filename,
// typically a gnarly /tmp directory, and returns the rest.
func sanitize(gopath, filename string) string {
	prefix := gopath + string(os.PathSeparator) + "src" + string(os.PathSeparator)
	return filepath.ToSlash(strings.TrimPrefix(filename, prefix))
}
