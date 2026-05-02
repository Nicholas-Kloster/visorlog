package main

import (
	"os"

	"github.com/Nicholas-Kloster/visorlog/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
