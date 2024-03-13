package main

import (
	"log"

	"github.com/snyk/cli-extension-sbom/pkg/sbom"

	"github.com/snyk/go-application-framework/pkg/devtools"
)

func main() {
	cmd, err := devtools.Cmd(sbom.Init)
	if err != nil {
		log.Fatal(err)
	}
	cmd.SilenceUsage = true
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
