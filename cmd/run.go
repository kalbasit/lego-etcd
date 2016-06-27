package cmd

import (
	"log"

	"github.com/coreos/etcd/client"
	"github.com/kalbasit/lego-etcd/legoetcd"
	"github.com/spf13/cobra"
	"github.com/xenolf/lego/acme"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: run,
}

func init() {
	RootCmd.AddCommand(runCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// runCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// runCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func run(cmd *cobra.Command, args []string) {
	// get all the values from the persistent flags
	pem, err := RootCmd.PersistentFlags().GetBool("pem")
	if err != nil {
		log.Fatalf("error loading the pem from the persistent flags: %s", err)
	}
	acceptTOS, err := RootCmd.PersistentFlags().GetBool("accept-tos")
	if err != nil {
		log.Fatalf("error loading the accept-tos from the persistent flags: %s", err)
	}
	dns, err := RootCmd.PersistentFlags().GetString("dns")
	if err != nil {
		log.Fatalf("error loading the dns from the persistent flags: %s", err)
	}
	httpAddr, err := RootCmd.PersistentFlags().GetString("http-addr")
	if err != nil {
		log.Fatalf("error loading the http-addr from the persistent flags: %s", err)
	}
	tlsAddr, err := RootCmd.PersistentFlags().GetString("tls-addr")
	if err != nil {
		log.Fatalf("error loading the tls-addr from the persistent flags: %s", err)
	}
	webRoot, err := RootCmd.PersistentFlags().GetString("webroot")
	if err != nil {
		log.Fatalf("error loading the webroot from the persistent flags: %s", err)
	}
	acmeServer, err := RootCmd.PersistentFlags().GetString("acme-server")
	if err != nil {
		log.Fatalf("error loading the acme-server from the persistent flags: %s", err)
	}
	csr, err := RootCmd.PersistentFlags().GetString("csr")
	if err != nil {
		log.Fatalf("error loading the csr from the persistent flags: %s", err)
	}
	email, err := RootCmd.PersistentFlags().GetString("email")
	if err != nil {
		log.Fatalf("error loading the email from the persistent flags: %s", err)
	}
	keyType, err := RootCmd.PersistentFlags().GetString("key-type")
	if err != nil {
		log.Fatalf("error loading the key-type from the persistent flags: %s", err)
	}
	domains, err := RootCmd.PersistentFlags().GetStringSlice("domains")
	if err != nil {
		log.Fatalf("error loading the domains from the persistent flags: %s", err)
	}
	etcdEndpoints, err := RootCmd.PersistentFlags().GetStringSlice("etcd-endpoints")
	if err != nil {
		log.Fatalf("error loading the etcd-endpoints from the persistent flags: %s", err)
	}

	// create an etcd client
	etcdClient, err := client.New(client.Config{Endpoints: etcdEndpoints})
	if err != nil {
		log.Fatalf("error creating a new etcd client: %s", err)
	}

	// create a new ACME client
	acmeClient, err := legoetcd.New(etcdClient, acmeServer, email, acme.KeyType(keyType), dns, webRoot, httpAddr, tlsAddr)
	if err != nil {
		log.Fatalf("error creating a new ACME server: %s", err)
	}

	// register the account and accept tos
	if err := acmeClient.RegisterAccount(acceptTOS); err != nil {
		if err == legoetcd.ErrMustAcceptTOS {
			log.Fatalf("Please re-run with --accept-tos to indicate you accept Let's encrypt terms of service.")
		}
		log.Fatalf("error registering the account: %s", err)
	}

	_ = pem
	_ = csr
	_ = domains
}
