package main

import (
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
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
