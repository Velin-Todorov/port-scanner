package cli

import (
	"fmt"
	"port-scanner/portScanner"
	"time"

	"github.com/spf13/cobra"
)

var simpleScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Checks if a port is opened",
	Run: func(cmd *cobra.Command, args []string) {
		host, _ := cmd.Flags().GetString("host")
		portScanner := portScanner.NewPortScanner()

		if len(host) == 0 {
			fmt.Println("No host passed")
			return
		}

		port, _ := cmd.Flags().GetString("port")

		if len(port) == 0 {
			fmt.Println("No port passed")
			return
		}

		res, err := portScanner.SimpleScan(host, port)

		if err != nil {
			fmt.Println(res)
			fmt.Printf("ERROR: %s", err.Error())
			return
		}

		fmt.Println(res)
	},
}

var vanillaScanCmd = &cobra.Command{
	Use:   "vscan",
	Short: "Checks all ports on a given host",
	Run: func(cmd *cobra.Command, args []string) {
		host, err := cmd.Flags().GetString("host")
		if err != nil || host == "" {
			fmt.Println("No host passed")
			return
		}

		ports, err := cmd.Flags().GetInt32("ports")
		portScanner := portScanner.NewPortScanner()

		if err != nil || ports <= 0 {
			fmt.Printf("Invalid ports value: %v\n", err)
			return
		}

		timeoutSeconds, err := cmd.Flags().GetInt32("timeout")
		if err != nil || timeoutSeconds < 0 {
			fmt.Printf("Invalid timeout value: %v\n", err)
			return
		}

		timeout := time.Duration(timeoutSeconds) * time.Second
		res, err := portScanner.VanillaScan(host, ports, timeout)

		if err != nil {
			fmt.Printf("ERROR: %s", err.Error())
			return
		}

		for _, result := range res {
			fmt.Println(result)
		}

	},
}

var sweepScanCmd = &cobra.Command{
	Use:   "swpscan",
	Short: "Performs a sweep scan",
	Run: func(cmd *cobra.Command, args []string) {
		hosts, err := cmd.Flags().GetString("hosts")

		if err != nil || len(hosts) == 0 {
			fmt.Println("No hosts passed")
			return
		}

		portScanner := portScanner.NewPortScanner()

		port, err := cmd.Flags().GetInt("port")

		if err != nil || port <= 0 {
			fmt.Printf("Invalid port value: %v\n", err)
			return
		}

		res, err := portScanner.SweepScan(hosts, port)

		if err != nil {
			fmt.Printf("ERROR: %s", err.Error())
		}

		for _, result := range res {
			fmt.Println(result)
		}
	},
}

func init() {
	rootCmd.AddCommand(simpleScanCmd)
	simpleScanCmd.Flags().String("host", "", "Host to check for open ports")
	simpleScanCmd.Flags().String("port", "", "Port to be checked if opened")

	rootCmd.AddCommand(vanillaScanCmd)
	vanillaScanCmd.Flags().String("host", "", "Host to check for open ports")
	vanillaScanCmd.Flags().Int32("ports", portScanner.DEFAULT_CONCURENT_PORTS, "How many concurrent ports at once")
	vanillaScanCmd.Flags().Int32("timeout", int32(portScanner.DEFAULT_TIMEOUT.Seconds()), "How long to try to connect to a port")

	vanillaScanCmd.MarkFlagRequired("host")

	rootCmd.AddCommand(sweepScanCmd)
	sweepScanCmd.Flags().String("hosts", "", "Host to check for open ports")
	sweepScanCmd.Flags().Int("port", 0, "Port to be checked if opened")

	sweepScanCmd.MarkFlagRequired("hosts")
	sweepScanCmd.MarkFlagRequired("port")
}
