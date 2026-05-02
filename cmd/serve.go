package cmd

import (
	"fmt"

	"github.com/Nicholas-Kloster/visorlog/store"
	"github.com/Nicholas-Kloster/visorlog/web"
	"github.com/spf13/cobra"
)

var (
	flagServeAddr string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the VisorLog web dashboard",
	Long:  `Serves the findings dashboard on the specified address (default :8765).`,
	RunE:  runServe,
}

func init() {
	serveCmd.Flags().StringVar(&flagServeAddr, "addr", "127.0.0.1:8765", "listen address")
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	db, err := store.Open(flagDB)
	if err != nil {
		return err
	}

	counts, _ := db.OpenCount()
	total := 0
	for _, n := range counts {
		total += n
	}
	fmt.Printf("[visorlog] db: %s (%d open findings)\n", flagDB, total)

	srv := web.New(db, flagServeAddr)
	return srv.Start()
}
