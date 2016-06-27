package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "lego-etcd",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig, checkFlags)

	RootCmd.PersistentFlags().Bool("pem", false, "Generate a .pem file by concatanating the .key and .crt files together.")
	RootCmd.PersistentFlags().BoolP("accept-tos", "a", false, "By setting this flag to true you indicate that you accept the current Let's Encrypt terms of service.")
	RootCmd.PersistentFlags().String("config", "", "config file (default is $HOME/.lego-etcd.yaml)")
	RootCmd.PersistentFlags().String("dns", "", "Solve a DNS challenge using the specified provider.")
	RootCmd.PersistentFlags().String("http-addr", "", "Set the port and interface to use for HTTP based challenges to listen on. Supported: interface:port or :port")
	RootCmd.PersistentFlags().String("tls-addr", "", "Set the port and interface to use for TLS based challenges to listen on. Supported: interface:port or :port")
	RootCmd.PersistentFlags().String("webroot", "", "Set the webroot folder to use for HTTP based challenges to write directly in a file in .well-known/acme-challenge")
	RootCmd.PersistentFlags().StringP("acme-server", "s", "https://acme-v01.api.letsencrypt.org/directory", "CA hostname (and optionally :port). The server certificate must be trusted in order to avoid further modifications to the client.")
	RootCmd.PersistentFlags().StringP("csr", "c", "", "Certificate signing request filename, if an external CSR is to be used")
	RootCmd.PersistentFlags().StringP("email", "m", "", "The account under which to register and renew the keys.")
	RootCmd.PersistentFlags().StringP("key-type", "k", "rsa2048", "Key type to use for private keys. Supported: rsa2048, rsa4096, rsa8192, ec256, ec384")
	RootCmd.PersistentFlags().StringSliceP("domains", "d", []string{}, "Domains for the certificate, can be specified multiple times.")
	RootCmd.PersistentFlags().StringSliceP("etcd-endpoints", "e", []string{}, "The etcd endpoints, can be specified multiple times.")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	}

	viper.SetConfigName(".lego-etcd") // name of config file (without extension)
	viper.AddConfigPath("$HOME")      // adding home directory as first search path
	viper.AutomaticEnv()              // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func checkFlags() {
	// we require either domains or csr, but not both
	csr, err := RootCmd.PersistentFlags().GetString("csr")
	if err != nil {
		log.Fatalf("error loading the csr from the persistent flags: %s", err)
	}
	domains, err := RootCmd.PersistentFlags().GetStringSlice("domains")
	if err != nil {
		log.Fatalf("error loading the domains from the persistent flags: %s", err)
	}
	if csr != "" && len(domains) > 0 {
		log.Fatal("Please specify either --domains/-d or --csr/-c, but not both")
	}
	if csr == "" && len(domains) == 0 {
		log.Fatal("Please specify either --domains/-d or --csr/-c, but not both")
	}

	// we require at least one etcd endpoint
	etcdEndpoints, err := RootCmd.PersistentFlags().GetStringSlice("etcd-endpoints")
	if err != nil {
		log.Fatalf("error loading the etcd-endpoints from the persistent flags: %s", err)
	}
	if len(etcdEndpoints) == 0 {
		log.Fatal("Please specify an etcd endpoint with --etcd-endpoints/-e")
	}
}
