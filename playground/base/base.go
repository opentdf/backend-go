package main

import (
	"flag"
	"fmt"
	"os"
	"plugin"
)

type Middleware interface {
	Inject()
}

type pluginFlagValues []string

func (i *pluginFlagValues) String() string {
	return fmt.Sprintf("<%v>", *i)
}

func (i *pluginFlagValues) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var pluginNames pluginFlagValues

// Derived from https://github.com/vladimirvivien/go-plugin-example
func main() {
	flag.Var(&pluginNames, "plugin", "Plugin paths to load")
	flag.Parse()

	if len(pluginNames) == 0 {
		fmt.Println("Please specify a plugin")
		os.Exit(1)
	}

	for _, p := range pluginNames {
		plug, err := plugin.Open(p)
		if err != nil {
			fmt.Printf("Unable to load %v", p)
			fmt.Println(err)
			os.Exit(1)
		}
		symMiddleware, err := plug.Lookup("Middleware")
		if err != nil {
			fmt.Printf("Unable to find Middleware in %v", p)
			fmt.Println(err)
			os.Exit(1)
		}

		mid, ok := symMiddleware.(Middleware)
		if !ok {
			fmt.Printf("unexpected type from module symbol in %v", p)
			os.Exit(1)
		}
		mid.Inject()
	}
}
