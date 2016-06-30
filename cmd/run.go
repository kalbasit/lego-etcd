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
	if err := acmeClient.RegisterAccount(etcdClient, acceptTOS); err != nil {
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
	if err := cert.Save(etcdClient, pem); err != nil {
		log.Fatalf("error saving the certificate: %s", err)
	}
}
