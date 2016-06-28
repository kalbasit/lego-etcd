// Copyright © 2016 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"log"
	"strings"

	"github.com/coreos/etcd/client"
	"github.com/kalbasit/lego-etcd/legoetcd"
	"github.com/spf13/cobra"
	"github.com/xenolf/lego/acme"
)

// renewCmd represents the renew command
var renewCmd = &cobra.Command{
	Use:   "renew",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: renew,
}

func init() {
	RootCmd.AddCommand(renewCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// renewCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// renewCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	renewCmd.Flags().BoolVar(&noBundle, "no-bundle", false, "Do not create a certificate bundle by adding the issuers certificate to the new certificate")
}

func renew(cmd *cobra.Command, args []string) {
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

	// load the certificate
	cert, err := legoetcd.LoadCert(etcdClient, domains)
	if err != nil {
		log.Fatalf("error load the certificate from etcd: %s", err)
	}

	// Renew the certificate
	if err := cert.Renew(acmeClient, !noBundle); err != nil {
		log.Fatalf("error renewing the certificate: %s", err)
	}

	// save the certificate
	if err := cert.Save(etcdClient, pem); err != nil {
		log.Fatalf("error saving the certificate: %s", err)
	}
}
