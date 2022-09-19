// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package analysis provides vulnerability analyzer
// using golang.org/x/vuln APIs.
package analysis

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/vuln/osv"
)

var vulnsJSONFile = ""

func init() {
	Analyzer.Flags.StringVar(&vulnsJSONFile, "vulns-json", vulnsJSONFile, "JSON file containing the list of ModuleVulns to be scanned")
}

var Analyzer = &analysis.Analyzer{
	Name:             Name,
	Doc:              Doc,
	Requires:         []*analysis.Analyzer{inspect.Analyzer},
	Run:              run,
	RunDespiteErrors: true,
	FactTypes:        []analysis.Fact{(*vulnFact)(nil)},
}

const Name = "vulns"
const Doc = `detect access to vulnerable symbols

The vuln analysis reports reference paths computed
based on the vulnerability information stored in
a json file (-vulns-json flag). The easiest way of
creating the vulns-json file is to use "vuln dump"
command that fetches relevant osv entries from GOVULNDB.`

// TODO: Support light-weight import-graph based analysis.
// For example, when we import a third-party package which
// references a vulnerable symbol directly or indirectly,
// treat that package completely vulnerable.

// A vulnFact records a path to a known vulnerable function.
// TODO: optimize the presentation to share common tails.
type vulnFact struct {
	// Vuln ID -> Reference path to a known vulnerable symbol.
	// Existence of an entry with an empty path indicates
	// the whole package is affected by the vulnerability.
	// (e.g. init)
	Path map[string][]string
}

func (f *vulnFact) AFact() {}
func (f *vulnFact) String() string {
	var b strings.Builder
	for k, v := range f.Path {
		b.WriteString(k)
		b.WriteString(":")

		b.WriteString(strings.Join(v, "\n\t"))
		b.WriteString(";")
	}
	return b.String()
}

// Catalog is the list of osv entries.
type Catalog struct {
	PkgToVulns map[string][]*osv.Entry
	Err        error

	// TODO(hyangah): ID to vulns to report details about detected vulnerability
	// (short description, href, fixed version)
}

// Refresh repopulates the Catalog.
func (c *Catalog) Refresh() {
	if vulnsJSONFile != "" {
		catalog.readFile(vulnsJSONFile)
	} else {
		catalog.Err = errors.New("catalog not initialized")
	}
	if catalog.Err != nil {
		log.Printf("catalog initialization failed: %v", catalog.Err)
	}
}

func (c *Catalog) readFile(catalogFile string) {
	f, err := os.Open(catalogFile)
	if err != nil {
		c.Err = err
		return
	}
	defer f.Close()
	var pkg2vulns map[string][]*osv.Entry
	if err := json.NewDecoder(f).Decode(&pkg2vulns); err != nil {
		c.Err = err
		return
	}
	c.PkgToVulns = pkg2vulns
	c.Err = nil
}

var (
	catalog Catalog
	once    sync.Once
)

func run(pass *analysis.Pass) (interface{}, error) {
	// TODO(hyangah): caching mechanism for use in a long-lived analysis server.
	once.Do(catalog.Refresh)

	if catalog.Err != nil {
		return nil, catalog.Err
	}

	if len(catalog.PkgToVulns) == 0 { // no vulnerability.
		return nil, nil
	}

	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	var (
		// bucket is the current receptacle for references.
		// It is updated as we enter each top-level declaration.
		bucket map[types.Object]bool

		// init holds references from package initialization
		// (init functions and global vars).
		// TODO: implement fully.
		init = make(map[types.Object]bool)

		// methods maps a named type to its declared methods.
		methods = make(map[*types.TypeName][]*types.Func)

		// maps each member of the package (including methods and init functions)
		// to the set of things it references.
		refs = make(map[types.Object]map[types.Object]bool)

		// importspec
		imports = make(map[types.Object]bool)
	)

	nodeTypes := []ast.Node{
		(*ast.ImportSpec)(nil),
		(*ast.Ident)(nil),
		(*ast.SelectorExpr)(nil),
		(*ast.FuncDecl)(nil),
		(*ast.ValueSpec)(nil),
		(*ast.TypeSpec)(nil),
	}
	inspect.WithStack(nodeTypes, func(n ast.Node, enter bool, stack []ast.Node) bool {
		if !enter {
			return true
		}

		switch n := n.(type) {
		case *ast.ImportSpec:
			obj, ok := pass.TypesInfo.Implicits[n]
			if !ok {
				obj = pass.TypesInfo.Defs[n.Name] // renaming import
			}
			if obj != nil {
				imports[obj] = true
			}

		case *ast.Ident:
			// referring identifier?
			if obj := pass.TypesInfo.Uses[n]; obj != nil {
				// Optimization: record only package-level decls and methods.
				switch obj.(type) {
				case *types.Func, *types.Var, *types.Const, *types.TypeName:
					// TODO: opt: ignore function-local objects.
					bucket[obj] = true
				}
			}

		case *ast.SelectorExpr:
			// field/method selection?
			if sel := pass.TypesInfo.Selections[n]; sel != nil {
				bucket[sel.Obj()] = true
			}

		case *ast.FuncDecl:
			// function, method, or package initializer
			obj := pass.TypesInfo.Defs[n.Name].(*types.Func)
			bucket = make(map[types.Object]bool)

			if n.Recv != nil { // method?
				// Add edge from receiver type name to this method.
				recv := obj.Type().(*types.Signature).Recv().Type()
				if p, ok := recv.(*types.Pointer); ok {
					recv = p.Elem()
				}
				name := recv.(*types.Named).Obj()
				methods[name] = append(methods[name], obj)

			} else if n.Name.Name == "init" { // package initializer?
				bucket = init
			}

			if obj != nil {
				refs[obj] = bucket
			}

		case *ast.ValueSpec:
			// Package-level var/const decl?
			if len(stack) == 3 { // [File GenDecl ValueSpec]
				bucket = make(map[types.Object]bool)
				for _, name := range n.Names {
					if def := pass.TypesInfo.Defs[name]; def != nil {
						refs[def] = bucket
					}
				}
			}

		case *ast.TypeSpec:
			// Package-level type decl?
			if len(stack) == 3 { // [File GenDecl TypeSpec]
				bucket = make(map[types.Object]bool)
				if def := pass.TypesInfo.Defs[n.Name]; def != nil {
					refs[def] = bucket
				}
			}
		}
		return true // proceed
	})

	// succs returns an unordered list of direct successors
	// of obj in the reference graph. A type implicitly refers
	// to its methods.
	succs := func(obj types.Object) (res []types.Object) {
		// Return the refs within the body of a func/type/var.
		if refs := refs[obj]; refs != nil {
			sortedRefs := make([]types.Object, 0, len(refs))
			for ref := range refs {
				sortedRefs = append(sortedRefs, ref)
			}
			// TODO: sort for stable iteration. Is there any better sorting function?
			sort.Slice(sortedRefs, func(i, j int) bool { return sortedRefs[i].Id() < sortedRefs[j].Id() })
			for _, ref := range sortedRefs {
				res = append(res, ref)
			}
		}

		// A type refers to its methods.
		if name, ok := obj.(*types.TypeName); ok {
			for _, method := range methods[name] {
				res = append(res, method)
			}
		}

		// TODO: support init functions.
		// Every member of a package implicitly depends
		// on the side effects of init functions and
		// global variable initializers, and adding
		// an init function to a package is actually
		// a common way to inject maliciousness.

		return res
	}
	format := func(obj types.Object) string {
		//return types.ObjectString(obj, (*types.Package).Name) // TODO: position
		return objectString(obj, pass.Fset)
	}
	// Simple depth-first path query with memoization.
	// The reported paths may be much longer than necessary.
	// TODO: Compute shortest paths using Floyd-Warshall.
	//
	// memo is a memoization of the path to a vulnerable object.
	// A nonempty slice indicates a path.
	// An empty non-nil slice indicates no path.
	// An nil slice marks a node as grey to detect cycles.
	memo := make(map[types.Object]map[string][]string)
	var findPath func(obj types.Object) map[string][]string
	findPath = func(obj types.Object) map[string][]string {
		path, ok := memo[obj]
		if !ok {
			memo[obj] = nil // mark grey to break cycles
			path = map[string][]string{}

			if vulns := catalog.isDirectlyVulnerable(obj); len(vulns) > 0 {
				// obj itself is vulnerable.
				o := []string{format(obj)}
				for _, v := range vulns {
					// format returns both qualified name and position info.
					// use only object name part (symbol) as the key.
					objName, _, _ := strings.Cut(o[0], " ")
					k := v + ":" + objName
					path[k] = o
				}
			} else if fact := (&vulnFact{}); pass.ImportObjectFact(obj, fact) {
				o := format(obj)
				// obj is indirectly vulnerable by induction over packages.
				for vuln, prev := range fact.Path {
					if len(prev) > 0 && prev[0] == o {
						path[vuln] = append([]string{}, prev...)
					} else {
						path[vuln] = append([]string{format(obj)}, prev...)
					}
				}
			} else {
				// Does obj indirectly reference a vulnerable function?
				o := format(obj)
				for _, succ := range succs(obj) {
					if path0 := findPath(succ); len(path0) > 0 {
						for vuln, prev := range path0 {
							if len(prev) > 0 && prev[0] == o {
								path[vuln] = append([]string{}, prev...)
							} else {
								path[vuln] = append([]string{o}, prev...)
							}
						}
					}
				}
			}

			if len(path) > 0 {
				memo[obj] = path
			}
		}
		return path
	}

	findings := map[string]bool{}

	packageFactPath := make(map[string][]string)

	for member := range imports {
		pkg := member.(*types.PkgName).Imported()

		var fact vulnFact
		if pass.ImportPackageFact(pkg, &fact) {
			for vuln, p := range fact.Path {
				p = append([]string{format(member)}, p...)
				id, _, _ := strings.Cut(vuln, ":")
				pass.Report(analysis.Diagnostic{
					Pos:      member.Pos(),
					End:      0,
					Category: vuln,
					Message:  id + "|" + strings.Join(p, "\t"),
				})
				if existing, ok := packageFactPath[vuln]; !ok || len(existing) > len(p) {
					packageFactPath[vuln] = p
				}
			}
		}
	}

	sortedRefs := make([]types.Object, 0, len(refs))
	for ref := range refs {
		sortedRefs = append(sortedRefs, ref)
	}
	for _, member := range sortedRefs {
		path := findPath(member)
		if len(path) == 0 {
			continue
		}

		for vuln, p := range path {
			if len(p) == 0 {
				continue
			}
			findings[vuln] = true
			id, _, _ := strings.Cut(vuln, ":")
			// TODO(hyangah): report only for packages that are requested to analyze.
			pass.Report(analysis.Diagnostic{
				Pos:      member.Pos(),
				End:      0,
				Category: vuln,
				// TODO(hyangah): find a better way to encode the call stack info.
				// Considered RelatedInformation, but that takes token.Pos, which
				// is strange given that we need to refer to the findings from
				// analysis of other packages.
				Message: id + "|" + strings.Join(p, "\t"),
				// TODO(hyangah): suggested fix - upgrade module
			})
		}
		// Propagate only exported object facts.
		if member.Exported() {
			v := &vulnFact{Path: path}
			pass.ExportObjectFact(member, v)
		}
		if member.Name() == "init" {
			for vuln, trace := range path {
				if _, ok := packageFactPath[vuln]; !ok {
					packageFactPath[vuln] = append([]string(nil), trace...)
				}
			}
		}
	}
	if len(packageFactPath) > 0 {
		pass.ExportPackageFact(&vulnFact{Path: packageFactPath})
	}
	return nil, nil
}

func (c *Catalog) isDirectlyVulnerable(o types.Object) []string {
	var vuln []string // vulnerability ID

	fn, ok := o.(*types.Func)
	if !ok {
		return nil
	}
	pkg := fn.Pkg()
	if pkg == nil {
		return nil
	}
	vulns := c.PkgToVulns[pkg.Path()]
	if len(vulns) == 0 {
		return nil
	}
	fnName := dbFuncName(fn)
	for _, v := range vulns {
		syms := affectedSymbols(pkg.Path(), v)
		if len(syms) == 0 {
			vuln = append(vuln, v.ID)
			continue // the entire package is vulnerable.
		}
		for _, s := range syms {
			if s == fnName {
				vuln = append(vuln, v.ID)
				continue
			}
		}
	}
	return vuln
}

// dbTypeFormat formats the name of t according how types
// are encoded in vulnerability database:
//   - pointer designation * is skipped
//   - full path prefix is skipped as well
func dbTypeFormat(t types.Type) string {
	switch tt := t.(type) {
	case *types.Pointer:
		return dbTypeFormat(tt.Elem())
	case *types.Named:
		return tt.Obj().Name()
	default:
		return types.TypeString(t, func(p *types.Package) string { return "" })
	}
}

func dbFuncName(f *types.Func) string {
	sig := f.Type().(*types.Signature)
	if sig.Recv() == nil {
		return f.Name()
	}
	return dbTypeFormat(sig.Recv().Type()) + "." + f.Name()
}

func affectedSymbols(pkg string, v *osv.Entry) []string {
	// TODO: memoize?
	var syms []string
	for _, a := range v.Affected {
		for _, p := range a.EcosystemSpecific.Imports {
			if p.Path == pkg {
				syms = append(syms, p.Symbols...)
			}
		}
		// TODO: should we use GOOS/GOARCH???
	}
	return syms
}

func exportedSymbols(in []string) []string {
	var out []string
	for _, s := range in {
		exported := true
		for _, part := range strings.Split(s, ".") {
			if !token.IsExported(part) {
				exported = false // exported only all parts in the symbol name are exported.
			}
		}
		if exported {
			out = append(out, s)
		}
	}
	return out
}

// objectString returns qualified object name followed by its position info (file:line:col)
func objectString(obj types.Object, fset *token.FileSet) string {
	var buf bytes.Buffer
	objectString0(&buf, obj)
	pos := fset.Position(obj.Pos())
	buf.WriteString(" ")
	buf.WriteString(pos.String())
	return buf.String()
}

// objectString0 returns a qualified name.
func objectString0(buf *bytes.Buffer, obj types.Object) {
	switch obj := obj.(type) {
	case *types.PkgName:
		fmt.Fprint(buf, obj.Pkg().Path())
		return

	case *types.Func:
		// For package-level objects, qualify the name.
		if obj.Pkg() != nil {
			buf.WriteString(obj.Pkg().Path())
			buf.WriteString(".")
		}
		buf.WriteString(dbFuncName(obj))
		return

	case *types.TypeName:

	default:
		//buf.WriteString(fmt.Sprintf("unknown type %T", obj))
	}
	// For package-level objects, qualify the name.
	if obj.Pkg() != nil {
		buf.WriteString(obj.Pkg().Path())
		buf.WriteString(".")
	}
	buf.WriteString(obj.Name())
}

// DumpVulnInfo writes the provided osv entry list to a temporary file
// and returns the file name.
func DumpVulnInfo(pkg2vulns map[string][]*osv.Entry) (fname string, err error) {
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
