package legoetcd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/etcd/client"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns/cloudflare"
	"github.com/xenolf/lego/providers/dns/digitalocean"
	"github.com/xenolf/lego/providers/dns/dnsimple"
	"github.com/xenolf/lego/providers/dns/dyn"
	"github.com/xenolf/lego/providers/dns/gandi"
	"github.com/xenolf/lego/providers/dns/googlecloud"
	"github.com/xenolf/lego/providers/dns/namecheap"
	"github.com/xenolf/lego/providers/dns/rfc2136"
	"github.com/xenolf/lego/providers/dns/route53"
	"github.com/xenolf/lego/providers/dns/vultr"
	"github.com/xenolf/lego/providers/http/webroot"
)

var (
	// ErrAddressInvalid is returned by New() when the address is not a valid
	// host:port.
	ErrAddressInvalid = errors.New("the address should be host:port")
)

func (c *Client) setupAccount(email string) error {
	// create a new account
	c.Account = NewAccount(email)
	// try loading from etcd
	if err := c.Account.LoadKey(c.ETCD); err != nil {
		if client.IsKeyNotFound(err) {
			// The account never existed, create one
			c.Account.GenerateKey()
		} else {
			return fmt.Errorf("error loading the account from etcd: %s", err)
		}
	}
	return nil
}

func (c *Client) setupChallenge(dns, webRoot, httpAddr, tlsAddr string) error {
	if webRoot != "" {
		provider, err := webroot.NewHTTPProvider(webRoot)
		if err != nil {
			return err
		}

		c.ACME.SetChallengeProvider(acme.HTTP01, provider)

		// --webroot=foo indicates that the user specifically want to do a HTTP challenge
		// infer that the user also wants to exclude all other challenges
		c.ACME.ExcludeChallenges([]acme.Challenge{acme.DNS01, acme.TLSSNI01})
	}

	// setup HTTP port
	if httpAddr != "" {
		if strings.Index(httpAddr, ":") == -1 {
			return ErrAddressInvalid
		}

		c.ACME.SetHTTPAddress(httpAddr)
	}

	// setup TLS port
	if tlsAddr != "" {
		if strings.Index(tlsAddr, "") == -1 {
			return ErrAddressInvalid
		}

		c.ACME.SetTLSAddress(tlsAddr)
	}

	if dns != "" {
		// setup the challenge provider
		var (
			err      error
			provider acme.ChallengeProvider
		)
		switch dns {
		case "cloudflare":
			provider, err = cloudflare.NewDNSProvider()
		case "digitalocean":
			provider, err = digitalocean.NewDNSProvider()
		case "dnsimple":
			provider, err = dnsimple.NewDNSProvider()
		case "dyn":
			provider, err = dyn.NewDNSProvider()
		case "gandi":
			provider, err = gandi.NewDNSProvider()
		case "gcloud":
			provider, err = googlecloud.NewDNSProvider()
		case "manual":
			provider, err = acme.NewDNSProviderManual()
		case "namecheap":
			provider, err = namecheap.NewDNSProvider()
		case "route53":
			provider, err = route53.NewDNSProvider()
		case "rfc2136":
			provider, err = rfc2136.NewDNSProvider()
		case "vultr":
			provider, err = vultr.NewDNSProvider()
		}
		if err != nil {
			return fmt.Errorf("error setting up the DNS provider: %s", err)
		}
		c.ACME.SetChallengeProvider(acme.DNS01, provider)

		// --dns=foo indicates that the user specifically want to do a DNS challenge
		// infer that the user also wants to exclude all other challenges
		c.ACME.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})
	}

	return nil
}
