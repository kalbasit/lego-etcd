package legoetcd

import (
	"errors"
	"fmt"

	"github.com/coreos/etcd/client"
	"github.com/xenolf/lego/acme"
)

var (
	// ErrMustAcceptTOS is returned of the TOS was not accepted and `acceptTOS`
	// is false.
	ErrMustAcceptTOS = errors.New("you must accept Let's encrypt terms of service")
)

// Client represents the legoetcd Client
type Client struct {
	*acme.Client
	Account *Account
}

// New returns a new ACME client configured with the challenge.
func New(ec client.Client, acmeServer, email string, keyType acme.KeyType, dns, webRoot, httpAddr, tlsAddr string) (*Client, error) {
	// create a new Client
	c := &Client{}
	// setup the account
	if err := c.setupAccount(ec, email); err != nil {
		return nil, err
	}
	// create a new ACME client
	acmeClient, err := acme.NewClient(acmeServer, c.Account, keyType)
	if err != nil {
		return nil, err
	}
	c.Client = acmeClient
	// setup the challenge
	if err := c.setupChallenge(dns, webRoot, httpAddr, tlsAddr); err != nil {
		return nil, err
	}

	return c, nil
}

// RegisterAccount registers the account
func (c *Client) RegisterAccount(ec client.Client, acceptTOS bool) error {
	// does the account needs to be registered?
	if err := c.Account.LoadRegistration(ec); err != nil {
		if client.IsKeyNotFound(err) {
			// register the account first
			if err := c.Account.Register(c.Client); err != nil {
				return fmt.Errorf("error registering the account with the ACME server: %s", err)
			}

			// save the account now
			if err := c.Account.Save(ec); err != nil {
				return fmt.Errorf("error saving the account to etcd: %s", err)
			}
		} else {
			return fmt.Errorf("error loading the account from etcd: %s", err)
		}
	}

	// do we need to accept TOS?
	if c.Account.GetRegistration().Body.Agreement == "" {
		if acceptTOS {
			// accept the TOS
			if err := c.Client.AgreeToTOS(); err != nil {
				return fmt.Errorf("could not agree to TOS: %s", err)
			}
			// save the account now
			if err := c.Account.Save(ec); err != nil {
				return fmt.Errorf("error saving the account to etcd: %s", err)
			}
		} else {
			return ErrMustAcceptTOS
		}
	}

	return nil
}
