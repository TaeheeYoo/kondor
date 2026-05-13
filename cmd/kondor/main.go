// SPDX-License-Identifier: GPL-2.0
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/patchwork-systems/kondor/internal/lb"
	"github.com/patchwork-systems/kondor/internal/server"
)

var apiURL = "http://127.0.0.1:8080"

func main() {
	root := &cobra.Command{
		Use:   "kondor",
		Short: "L3 DSR load balancer with XDP",
	}

	root.PersistentFlags().StringVar(&apiURL, "api", apiURL, "API server URL")

	root.AddCommand(serveCmd())
	root.AddCommand(vipCmd())
	root.AddCommand(realCmd())
	root.AddCommand(statsCmd())
	root.AddCommand(flushCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func serveCmd() *cobra.Command {
	var (
		intf    string
		port    int
		mac     string
		offload bool
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the kondor daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := lb.NewManager()

			if err := mgr.Attach(intf, offload); err != nil {
				return fmt.Errorf("attach to %s: %w", intf, err)
			}
			defer mgr.Close()

			if mac != "" {
				hwAddr, err := net.ParseMAC(mac)
				if err != nil {
					return fmt.Errorf("parse MAC: %w", err)
				}
				if err := mgr.SetRouterMAC(hwAddr); err != nil {
					return fmt.Errorf("set MAC: %w", err)
				}
			}

			fmt.Printf("kondor: attached to %s, API on :%d\n", intf, port)

			r := server.New(mgr)

			go r.Run(fmt.Sprintf(":%d", port))

			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			<-sig

			fmt.Println("\nkondor: shutting down")
			return nil
		},
	}

	cmd.Flags().StringVar(&intf, "intf", "", "Network interface")
	cmd.Flags().IntVar(&port, "port", 8080, "API listen port")
	cmd.Flags().StringVar(&mac, "mac", "", "Router MAC address (next-hop)")
	cmd.Flags().BoolVar(&offload, "offload", false, "Use XDP hardware offload mode")
	cmd.MarkFlagRequired("intf")

	return cmd
}

func vipCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vip",
		Short: "Manage VIPs",
	}

	addCmd := &cobra.Command{
		Use:   "add <address> <port> <tcp|udp>",
		Short: "Add a VIP",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]interface{}{
				"address":  args[0],
				"port":     parsePort(args[1]),
				"protocol": args[2],
			}
			return apiPost("/api/v1/vips", body)
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List VIPs",
		RunE: func(cmd *cobra.Command, args []string) error {
			return apiGet("/api/v1/vips")
		},
	}

	delCmd := &cobra.Command{
		Use:   "delete <address> <port> <tcp|udp>",
		Short: "Delete a VIP",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]interface{}{
				"address":  args[0],
				"port":     parsePort(args[1]),
				"protocol": args[2],
			}
			return apiDelete("/api/v1/vips", body)
		},
	}

	cmd.AddCommand(addCmd, listCmd, delCmd)
	return cmd
}

func realCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "real",
		Short: "Manage reals",
	}

	var vipFlag string

	addCmd := &cobra.Command{
		Use:   "add <real_address>",
		Short: "Add a real server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vAddr, vPort, vProto, err := parseVIPFlag(vipFlag)
			if err != nil {
				return err
			}
			body := map[string]interface{}{
				"vip_address":  vAddr,
				"vip_port":     vPort,
				"vip_protocol": vProto,
				"real_address": args[0],
			}
			return apiPost("/api/v1/vips/reals", body)
		},
	}
	addCmd.Flags().StringVar(&vipFlag, "vip", "", "VIP (e.g. 10.0.0.1:80/tcp)")
	addCmd.MarkFlagRequired("vip")

	delCmd := &cobra.Command{
		Use:   "delete <real_address>",
		Short: "Delete a real server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vAddr, vPort, vProto, err := parseVIPFlag(vipFlag)
			if err != nil {
				return err
			}
			body := map[string]interface{}{
				"vip_address":  vAddr,
				"vip_port":     vPort,
				"vip_protocol": vProto,
				"real_address": args[0],
			}
			return apiDelete("/api/v1/vips/reals", body)
		},
	}
	delCmd.Flags().StringVar(&vipFlag, "vip", "", "VIP (e.g. 10.0.0.1:80/tcp)")
	delCmd.MarkFlagRequired("vip")

	cmd.AddCommand(addCmd, delCmd)
	return cmd
}

func statsCmd() *cobra.Command {
	var vipFlag string
	var all bool

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			if all || vipFlag == "" {
				return apiGet("/api/v1/stats/global")
			}
			vAddr, vPort, vProto, err := parseVIPFlag(vipFlag)
			if err != nil {
				return err
			}
			return apiGet(fmt.Sprintf("/api/v1/stats?address=%s&port=%d&protocol=%s",
				vAddr, vPort, vProto))
		},
	}

	cmd.Flags().StringVar(&vipFlag, "vip", "", "VIP (e.g. 10.0.0.1:80/tcp)")
	cmd.Flags().BoolVar(&all, "all", false, "Show global stats")

	return cmd
}

func flushCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "flush",
		Short: "Remove all VIPs (not implemented yet)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("flush: not implemented yet")
			return nil
		},
	}
}

func parseVIPFlag(s string) (string, int, string, error) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return "", 0, "", fmt.Errorf("invalid VIP format, expected addr:port/proto")
	}
	proto := parts[1]
	host, portStr, err := net.SplitHostPort(parts[0])
	if err != nil {
		return "", 0, "", fmt.Errorf("invalid VIP address:port: %w", err)
	}
	return host, parsePort(portStr), proto, nil
}

func parsePort(s string) int {
	var p int
	fmt.Sscanf(s, "%d", &p)
	return p
}

func apiPost(path string, body interface{}) error {
	data, _ := json.Marshal(body)
	resp, err := http.Post(apiURL+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return printResponse(resp)
}

func apiGet(path string) error {
	resp, err := http.Get(apiURL + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return printResponse(resp)
}

func apiDelete(path string, body interface{}) error {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodDelete, apiURL+path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return printResponse(resp)
}

func printResponse(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	var out bytes.Buffer
	if json.Indent(&out, body, "", "  ") == nil {
		fmt.Println(out.String())
	} else {
		fmt.Println(string(body))
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("API returned %d", resp.StatusCode)
	}
	return nil
}
