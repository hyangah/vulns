// testutils is a collection of utilities useful for vulncheck api testing
package testutils

import (
	"context"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"

	"github.com/hyangah/vulns/testutils/internal/database"
)

// Database returns a read-only DB containing the provided
// txtar-format collection of vulnerability reports.
// Each vulnerability report is a YAML file whose format
// is defined in golang.org/x/vulndb/doc/format.md.
// A report file name must have the id as its base name,
// and have .yaml as its extension.
// The constructed database should be readable using
// golang.org/x/vuln APIs by setting VULNDB environment
// variable to DB.URI() value.
func NewDatabase(ctx context.Context, txtarReports []byte) (*DB, error) {
	disk, err := ioutil.TempDir("", "vulndb-test")
	if err != nil {
		return nil, err
	}
	if err := database.Generate(ctx, txtarReports, disk, false); err != nil {
		os.RemoveAll(disk)
		return nil, err
	}

	return &DB{disk: disk}, nil
}

type DB struct {
	disk string
}

func (db *DB) URI() string {
	u := url.URL{
		Scheme: "file",
		Path:   filepath.ToSlash(db.disk),
	}
	return u.String()
}

func (db *DB) Clean() error {
	return os.RemoveAll(db.disk)
}
