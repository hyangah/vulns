package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/hyangah/vulns/internal/osvutil"
	"github.com/hyangah/vulns/testutils"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
)

func Test(t *testing.T) {
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "work",
			Files: map[string]interface{}{
				"x/x.go": `
			package x
			import "work/y"
			func X() {	y.Y() } // want "GO02\\|.*" X:"GO02:.*"
			`,
				"y/y.go": `
			package y
			import a "a.com/m/vuln"
			import b "b.com/m/vuln"
			func Y() { // want "GO02\\|.*" Y:"GO02:.*"
				b.Vuln()
				a.OK()
			}			
		`}},
		{
			Name: "a.com/m@v0.0.5",
			Files: map[string]interface{}{
				"go.mod": `module a.com/m`,
				"vuln/vuln.go": `
			package vuln
			func Vuln() {}
			func OK() {}
		`}},
		{
			Name: "b.com/m@v1.0.1",
			Files: map[string]interface{}{
				"go.mod": `module b.com/m`,
				"vuln/vuln.go": `
			package vuln
			func Vuln() {}
			func OK() {}
		`}},
	})
	defer e.Cleanup()
	pkgs, err := LoadPackages(e, "work/...")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatal("failed to load x and y test packages")
	}

	in := []byte(`
-- GO01.yaml --
modules:
  - module: a.com/m
    versions:
      - fixed: 0.0.5
    packages:
      - package: a.com/m/vuln
        symbols:
          - Vuln
description: |
    Something
published: 2021-04-14T20:04:52Z
-- GO02.yaml --
modules:
  - module: b.com/m
    versions:
      - fixed: 1.1.0
    packages:
      - package: b.com/m/vuln
        symbols:
          - Vuln
description: |
    Something
published: 2021-04-14T20:04:52Z
`)
	db, err := testutils.NewDatabase(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Clean()

	var opts client.Options
	cli, err := client.NewClient([]string{db.URI()}, opts)
	if err != nil {
		t.Fatal(err)
	}
	pkg2vulns, err := osvutil.FetchOSVEntries(context.Background(), cli, pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg2vulns) == 0 {
		t.Fatal(err)
	}

	vulnsJSONFile, err := DumpVulnInfo(pkg2vulns)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(vulnsJSONFile)

	// Print the results.
	Analyzer.Flags.Set("vulns-json", vulnsJSONFile)
	RunWithPackages(t, e.Config.Dir, Analyzer, pkgs)
}

func LoadPackages(e *packagestest.Exported, patterns ...string) ([]*packages.Package, error) {
	e.Config.Mode |= packages.NeedModule | packages.NeedName | packages.NeedFiles |
		packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedTypes |
		packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps
	return packages.Load(e.Config, patterns...)
}

type mockClient struct {
	client.Client
	ret map[string][]*osv.Entry
}

func (mc *mockClient) initDB(dbJSON string) error {
	var db map[string][]*osv.Entry
	if err := json.Unmarshal([]byte(dbJSON), &db); err != nil {
		return err
	}
	mc.ret = db
	return nil
}

func (mc *mockClient) GetByModule(ctx context.Context, a string) ([]*osv.Entry, error) {
	if mc == nil {
		return nil, fmt.Errorf("no network")
	}
	return mc.ret[a], nil
}
