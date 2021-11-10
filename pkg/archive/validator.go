package archive

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
)

// TODO add validate function to be used by CLI and web
// find file
// check zip
// check contents
// check payload is correct
// check integrity versus manifest

// Valid reports errors if r is an invalid TDF3 archive.
func Valid(r io.Reader) error {
	buff := bytes.NewBuffer([]byte{})
	size, err := io.Copy(buff, r)
	if err != nil {
		return err
	}
	reader := bytes.NewReader(buff.Bytes())
	zipReader, err := zip.NewReader(reader, size)
	if err != nil {
		return err
	}
	for _, f := range zipReader.File {
		if strings.Contains(f.Name, "manifest") {
			fmt.Println(f.FileHeader)
			rc, err := f.Open()
			if err != nil {
				return err
			}
			manifest, err := ioutil.ReadAll(rc)
			if err != nil {
				return err
			}
			_ = rc.Close()
			fmt.Println(manifest)
		}
	}
	return err
}
