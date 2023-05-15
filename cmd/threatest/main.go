package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use: "threatest",
}

func init() {
	rootCmd.AddCommand(NewRunCommand())
	rootCmd.AddCommand(NewLintCommand())
}

func main() {
	if os.Getenv("THREATEST_DEBUG") == "1" {
		log.SetLevel(log.DebugLevel)
	}
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
