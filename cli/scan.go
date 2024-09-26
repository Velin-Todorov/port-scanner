package cli

import (
	"fmt"
	"port-scanner/pkg"

	"github.com/spf13/cobra"
)

var simpleScanCmd = &cobra.Command{
	Use: "scan",
	Short: "Checks if a port is opened",
	Run: func(cmd *cobra.Command, args []string) {
		host, _ := cmd.Flags().GetString("host")

		if len(host) == 0 {
			fmt.Println("No host passed")
			return
		}

		port, _ := cmd.Flags().GetString("port")

		if len(port) == 0 {
			fmt.Println("No port passed")
			return
		}

		res, err := pkg.SimpleScan(host, port)

		if err != nil {
			fmt.Println(res)
			fmt.Printf("ERROR: %s", err.Error())
			return 
		}

		fmt.Println(res)
	},
}

var vanillaScanCmd = &cobra.Command{
	Use: "scanAll",
	Short: "Checks all ports on a given host",
	Run: func(cmd *cobra.Command, args []string) {
		host, _ := cmd.Flags().GetString("host")

		if len(host) == 0 {
			fmt.Println("No host passed")
			return
		}

		pkg.VanillaScan(host)
	},
}

func init() {
	rootCmd.AddCommand(simpleScanCmd)
	simpleScanCmd.Flags().String("host", "", "Host to check for open ports")
	simpleScanCmd.Flags().String("port", "", "Port to be checked if opened")

	rootCmd.AddCommand(vanillaScanCmd)
	vanillaScanCmd.Flags().String("host", "", "Host to check for open ports")
}