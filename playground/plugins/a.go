package plugins

import "fmt"

type a string

func (g a) Inject() {
	fmt.Println("Injected A")
}

var Middleware a
