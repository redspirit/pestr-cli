package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"pestr/internal/extract"
	"pestr/internal/patch"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "extract":
		pattern := flag.NewFlagSet("extract", flag.ExitOnError)
		var p string
		pattern.StringVar(&p, "p", "", "alternative regex pattern for filtering strings")
		pattern.StringVar(&p, "pattern", "", "alternative regex pattern for filtering strings")
		pattern.Parse(os.Args[2:])
		if err := runExtract(pattern.Arg(0), &p); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "patch":
		patchFlags := flag.NewFlagSet("patch", flag.ExitOnError)
		var jsonPath string
		var outPath string
		patchFlags.StringVar(&jsonPath, "json", "", "path to json with translations (if omitted, read from stdin)")
		patchFlags.StringVar(&outPath, "out", "", "output path for patched exe (required)")

		args := os.Args[2:]
		exePath := ""
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			exePath = args[0]
			args = args[1:]
		}
		patchFlags.Parse(args)
		if exePath == "" {
			exePath = patchFlags.Arg(0)
		}

		if err := runPatch(exePath, jsonPath, outPath); err != nil {
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

func runExtract(path string, pattern *string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var out []byte
	if pattern == nil || *pattern == "" {
		out, err = extract.Extract(data)
	} else {
		// The user's pattern is for ASCII text, so we embed it into the full regex pattern
		// with global (g) and case-insensitive (i) flags already included.
		fullPattern := fmt.Sprintf("(?im)^[%s]+$", *pattern)
		compiled, err := extract.CompilePattern(fullPattern)
		if err != nil {
			return fmt.Errorf("invalid pattern: %w", err)
		}
		out, err = extract.ExtractWithPattern(data, compiled)
	}
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

func runPatch(exePath, jsonPath, outPath string) error {
	if outPath == "" {
		return fmt.Errorf("missing required --out parameter")
	}
	return patch.Run(exePath, jsonPath, outPath)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  pestr extract <file.exe> [-p <pattern>]")
	fmt.Fprintln(os.Stderr, "  pestr patch <file.exe> --out patched.exe [--json localisation.json]")
}
