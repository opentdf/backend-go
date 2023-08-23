package plugins

import "fmt"

type b string

func (g b) Inject() {
	fmt.Println("Injected B")
}

var Middleware b
