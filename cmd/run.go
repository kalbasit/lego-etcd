package cmd

import (
	"log"
	"os"
	"strings"

	"github.com/coreos/etcd/client"
	"github.com/kalbasit/lego-etcd/legoetcd"
	"github.com/spf13/cobra"
	"github.com/xenolf/lego/acme"
)

var noBundle bool

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

	runCmd.Flags().BoolVar(&noBundle, "no-bundle", false, "Do not create a certificate bundle by adding the issuers certificate to the new certificate")
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

	// figure our the key-type
	var kt acme.KeyType
	switch strings.ToUpper(keyType) {
	case "RSA2048":
		kt = acme.RSA2048
	case "RSA4096":
		kt = acme.RSA4096
	case "RSA8192":
		kt = acme.RSA8192
	case "EC256":
		kt = acme.EC256
	case "EC384":
		kt = acme.EC384
	default:
		log.Fatalf("unknown key type %q", keyType)
	}

	// create a new ACME client
	acmeClient, err := legoetcd.New(etcdClient, acmeServer, email, kt, dns, webRoot, httpAddr, tlsAddr)
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

	// create a new certificate for domains or csr.
	cert, failures := acmeClient.NewCert(domains, csr, !noBundle)
	if len(failures) > 0 {
		for k, v := range failures {
			log.Printf("[%s] Could not obtain certificates\n\t%s", k, v.Error())
		}
		os.Exit(1)
	}

	// save the certificate
	if err := cert.Save(pem); err != nil {
		log.Fatalf("error saving the certificate: %s", err)
	}
}
