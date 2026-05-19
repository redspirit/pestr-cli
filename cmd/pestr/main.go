package main

import (
	"fmt"
	"os"

	"pestr/internal/extract"
)

func main() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "extract":
		if err := runExtract(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func runExtract(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out, err := extract.Extract(data)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write([]byte("\n"))
	return err
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pestr extract <file.exe>")
}
