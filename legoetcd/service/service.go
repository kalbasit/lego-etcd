package service

import (
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/net/context"

	"github.com/coreos/etcd/client"
	"github.com/kalbasit/lego-etcd/legoetcd"
	"github.com/xenolf/lego/acme"
)

const (
	accountLockKey = "/lego/accounts/%s/lock"
	certLockKey    = "/lego/certificates/%s.lock"
)

var (
	// ErrGeneratingCert is returned when there's a failure generating a new certificate.
	ErrGeneratingCert = errors.New("an error occurred while generating the certificate, please check the log for more information")
	// ErrTOSNotAccepted is returns if the acceptTOS was set to false and the account has never accepted the TOS.
	ErrTOSNotAccepted = errors.New("Let's encrypt terms of service was not accepted")

	minimumDurationForRenewal = 45 * 24 * time.Hour
)

// Service represents a lego-etcd service that is able to manage the
// certificate for the given domains by generating certificates through Let's
// encrypt, storing them in etcd and renew them as well. The service is fully
// managed.
type Service struct {
	// CertChan is the channel where the service sends out the certificate at the
	// retrieval and at the renewal time.
	CertChan chan *legoetcd.Cert
	// StopChan if closed will stop the service.
	StopChan chan struct{}
	// KeyType is the crypto type for the key, Supported: rsa2048, rsa4096,
	// rsa8192, ec256, ec384.
	KeyType acme.KeyType
	// NoBundle disables bundling of the issuer certificate along with the
	// domain's certificate.
	NoBundle bool

	acceptTOS   bool
	acmeServer  string
	csrFile     string
	dns         string
	domains     []string
	email       string
	etcdConfig  client.Config
	generatePEM bool
	webroot     string
}

// New returns a new service, the default keyType is RSA2048 but you may change
// by setting the KeyType on the returned service. By default, the service will
// generate a bundled certificate (containing the issuer certificate and your
// certificate). To disable bundling, set `NoBundle` to true.
func New(etcdConfig client.Config, acmeServer, email string, domains []string, csrFile string, acceptTOS, generatePEM bool, dns, webroot string) *Service {
	return &Service{
		CertChan: make(chan *legoetcd.Cert),
		StopChan: make(chan struct{}),
		KeyType:  acme.RSA2048,

		acceptTOS:   acceptTOS,
		acmeServer:  acmeServer,
		csrFile:     csrFile,
		dns:         dns,
		domains:     domains,
		email:       email,
		etcdConfig:  etcdConfig,
		generatePEM: generatePEM,
		webroot:     webroot,
	}
}

// Run starts the certificate loop
func (s *Service) Run() error {
	// create an etcd client
	etcdClient, err := client.New(s.etcdConfig)
	// create a new keys API
	kapi := client.NewKeysAPI(etcdClient)
	// initialize the account
	if err := s.createAccountIfNecessary(etcdClient); err != nil {
		return err
	}
	// create a new ACME client
	// TODO: httpAddr and tlsAddr support
	acmeClient, err := legoetcd.New(etcdClient, s.acmeServer, s.email, s.KeyType, s.dns, s.webroot, "", "")
	if err != nil {
		return fmt.Errorf("error creating a new ACME server: %s", err)
	}
	// register the account and accept tos
	if err := acmeClient.RegisterAccount(etcdClient, s.acceptTOS); err != nil {
		if err == legoetcd.ErrMustAcceptTOS {
			return ErrTOSNotAccepted
		}
		return fmt.Errorf("error registering the account: %s", err)
	}
	// watch the certificate on etcd, and send the certificate down the channel.
	// initialize the certificate
	cert, err := s.generateCertificateIfNecessary(etcdClient, acmeClient)
	if err != nil {
		return err
	}
	go func() {
		w := kapi.Watcher(cert.CertPath(), nil)
		for {
			done := make(chan struct{})
			ctx, cancelFunc := context.WithCancel(context.Background())
			go func(done chan struct{}) {
				// block until either a stop which cancels the context or a stop event
				// which is sent after the current next unblocks.
				select {
				case <-s.StopChan:
					cancelFunc()
				case <-done:
				}
			}(done)
			resp, err := w.Next(ctx)
			close(done)
			cancelFunc()
			if err != nil {
				log.Printf("received an error fetching the next change to the certificate %q: %s", cert.CertPath(), err)
			}
			if resp.Action != "get" && resp.Action != "delete" {
				// sleep for one second to allow whoever updating to finish up with the
				// key as well.
				if err := cert.Reload(etcdClient); err != nil {
					log.Printf("error reloading the certificate: %s", err)
				} else {
					s.CertChan <- cert
				}
			}
		}
	}()
	// send the cert down the channel (this locks up until the calling process can receive).
	s.CertChan <- cert
	// start the update loop
	t := time.NewTicker(12 * time.Hour)
	for {
		select {
		case <-t.C:
			// do we need to renew the certificate?
			exp, err := cert.ExpiresIn()
			if err != nil {
				log.Printf("was not able to query the certificate expiration date: %s", err)
				goto nextChange
			}
			if exp > minimumDurationForRenewal {
				// we must renew the certificate, grab a lock
				lockPath := fmt.Sprintf(certLockKey, s.domains[0])
				if err := s.Lock(etcdClient, lockPath); err != nil {
					if err == ErrLockExists {
						// someone else grabbed the lock, wait for it to be unlocked
						if err := s.WaitForLockDeletion(etcdClient, lockPath); err != nil {
							log.Printf("error while waiting for the lock to be unlocked: %s", err)
							goto nextChange
						}
					}
				} else {
					// lock was grabbed, renew the certificate
					if err := cert.Renew(acmeClient, s.NoBundle); err != nil {
						log.Printf("error while renewing the certificate: %s", err)
						goto nextChange
					}
					// save the certificate
					if err := cert.Save(etcdClient, s.generatePEM); err != nil {
						log.Printf("error saving the certificate: %s", err)
						goto nextChange
					}
				}
			}
		case <-s.StopChan:
			return nil
		}
	nextChange:
		// this is the end of for, so the loop will start again.
	}
}

func (s *Service) generateCertificateIfNecessary(etcdClient client.Client, acmeClient *legoetcd.Client) (*legoetcd.Cert, error) {
	// try loading the certificate
	cert, err := legoetcd.LoadCert(etcdClient, s.domains)
	if err == nil {
		return cert, nil
	}
	// we do not have a certificate, create a lock and create it - or wait for
	// another process to do so.
	lockPath := fmt.Sprintf(certLockKey, s.domains[0])
	// try to grab a lock
	if err := s.Lock(etcdClient, lockPath); err != nil {
		if err == ErrLockExists {
			// someone else grabbed the key, wait for it to be unlocked
			if err := s.WaitForLockDeletion(etcdClient, lockPath); err != nil {
				return nil, err
			}
		}
	} else {
		// lock was grabbed, create the new account.
		defer s.Unlock(etcdClient, lockPath)
		// create a new certificate for domains or csr.
		cert, failures := acmeClient.NewCert(s.domains, s.csrFile, s.NoBundle)
		if len(failures) > 0 {
			for k, v := range failures {
				log.Printf("[%s] Could not obtain certificates\n\t%s", k, v.Error())
			}
			return nil, ErrGeneratingCert
		}
		// save the certificate
		if err := cert.Save(etcdClient, s.generatePEM); err != nil {
			return nil, fmt.Errorf("error saving the certificate: %s", err)
		}
	}
	// finally make sure we can load the cert and return it
	if err := cert.Reload(etcdClient); err != nil {
		return nil, fmt.Errorf("was expecting the certificate to be saved: %s", err)
	}
	return cert, nil
}

func (s *Service) createAccountIfNecessary(etcdClient client.Client) error {
	// do we have an account?
	acc := legoetcd.NewAccount(s.email)
	err := acc.Load(etcdClient)
	if err == nil {
		// ok we have an account, short-circuit out of this func
		return nil
	}
	// we got an error, is it a not-found error (means account does not exist)?
	if client.IsKeyNotFound(err) {
		// we do not have an account, create a lock and create it - or wait for
		// another process to do so.
		lockPath := fmt.Sprintf(accountLockKey, s.email)
		if err := s.Lock(etcdClient, lockPath); err != nil {
			if err == ErrLockExists {
				// someone else grabbed the key, wait for it to be unlocked
				if err := s.WaitForLockDeletion(etcdClient, lockPath); err != nil {
					return err
				}
			}
		} else {
			// lock was grabbed, create the new account.
			defer s.Unlock(etcdClient, lockPath)
			if err := acc.GenerateKey(); err != nil {
				return err
			}
			if err := acc.Save(etcdClient); err != nil {
				return err
			}
		}
		// finally make sure we can load the account (we just need the key actually).
		if err := acc.LoadKey(etcdClient); err != nil {
			return fmt.Errorf("was expecting the account to have a key: %s", err)
		}

		return nil
	}
	// we got a non-404 error, return it
	return err
}
