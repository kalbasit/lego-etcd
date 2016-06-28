package legoetcd

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"golang.org/x/net/context"

	"github.com/coreos/etcd/client"
	"github.com/xenolf/lego/acme"
)

const (
	certKey = "/lego/certificates/%s.cert"
	keyKey  = "/lego/certificates/%s.key"
	metaKey = "/lego/certificates/%s.json"
	pemKey  = "/lego/certificates/%s.pem"
)

// ErrNoPemForCSR is returned when there is no private key.
var ErrNoPemForCSR = errors.New("unable to save pem without private key; are you using a CSR?")

// Cert represents a domain certificate
type Cert struct {
	Domains []string
	CSR     *x509.CertificateRequest
	Cert    acme.CertificateResource
}

// NewCert obtains a new certificate for the domains or the csr.
func (c *Client) NewCert(domains []string, csrFile string, bundle bool) (*Cert, map[string]error) {
	var (
		cert     acme.CertificateResource
		failures map[string]error
		csr      *x509.CertificateRequest
	)
	{
		var err error

		// generate a domains certificate
		if len(domains) > 0 {
			cert, failures = c.Client.ObtainCertificate(domains, bundle, nil)
		} else {
			// read the CSR
			csr, err = readCSRFile(csrFile)
			if err != nil {
				// we couldn't read the CSR
				failures = map[string]error{"csr": err}
			} else {
				// obtain a certificate for this CSR
				cert, failures = c.Client.ObtainCertificateForCSR(*csr, bundle)
			}
		}
	}
	if len(failures) > 0 {
		return nil, failures
	}

	return &Cert{
		Domains: domains,
		CSR:     csr,
		Cert:    cert,
	}, nil
}

// LoadCert loads the certificate from ETCD
func LoadCert(ec client.Client, domains []string) (*Cert, error) {
	cert := &Cert{
		Domains: domains,
		Cert:    acme.CertificateResource{},
	}

	if err := cert.loadMeta(ec); err != nil {
		return nil, err
	}
	if err := cert.loadCert(ec); err != nil {
		return nil, err
	}
	if err := cert.loadKey(ec); err != nil {
		return nil, err
	}

	return cert, nil
}

// Reload re-reads the certificate from etcd.
func (c *Cert) Reload(ec client.Client) error {
	if err := c.loadMeta(ec); err != nil {
		return err
	}
	if err := c.loadCert(ec); err != nil {
		return err
	}
	if err := c.loadKey(ec); err != nil {
		return err
	}
	return nil
}

// MetaPath returns the path where the metadata of this certificate is store on etcd.
func (c *Cert) MetaPath() string { return fmt.Sprintf(metaKey, c.Domains[0]) }

// CertPath returns the path where the CRT of this certificate is store on etcd.
func (c *Cert) CertPath() string { return fmt.Sprintf(certKey, c.Domains[0]) }

// KeyPath returns the path where the PrivateKey of this certificate is store on etcd.
func (c *Cert) KeyPath() string { return fmt.Sprintf(keyKey, c.Domains[0]) }

// PemPath returns the path where the PEM of this certificate is store on etcd.
func (c *Cert) PemPath() string { return fmt.Sprintf(pemKey, c.Domains[0]) }

// Renew renews the certificate through the ACME client.
func (c *Cert) Renew(ac *Client, bundle bool) error {
	cert, err := ac.RenewCertificate(c.Cert, bundle)
	if err != nil {
		return err
	}
	c.Cert = cert
	return nil
}

// Expiration returns the certificate's expiration date and time.
func (c *Cert) Expiration() (time.Time, error) {
	return acme.GetPEMCertExpiration(c.Cert.Certificate)
}

// ExpiresIn returns the duration until the certificate expires.
func (c *Cert) ExpiresIn() (time.Duration, error) {
	// get the expiration date/time
	expTime, err := acme.GetPEMCertExpiration(c.Cert.Certificate)
	if err != nil {
		return 0, err
	}
	return expTime.Sub(time.Now()), nil
}

// PEM returns this certificate PEM-encoded.
func (c *Cert) PEM() []byte {
	return bytes.Join([][]byte{c.Cert.Certificate, c.Cert.PrivateKey}, nil)
}

// Save saves the certificate to etcd.
func (c *Cert) Save(ec client.Client, pem bool) error {
	if err := c.saveCert(ec); err != nil {
		return err
	}
	if err := c.saveMeta(ec); err != nil {
		return err
	}
	if c.Cert.PrivateKey != nil {
		if err := c.saveKey(ec); err != nil {
			return err
		}
		if pem {
			if err := c.savePem(ec); err != nil {
				return err
			}
		}
	} else if pem {
		return ErrNoPemForCSR
	}

	return nil
}

func (c *Cert) loadMeta(ec client.Client) error {
	// create a new keys API
	kapi := client.NewKeysAPI(ec)
	// get it from etcd
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	resp, err := kapi.Get(ctx, c.MetaPath(), nil)
	if err != nil {
		return err
	}
	cancelFunc()
	// unmarshal right to the struct
	return json.Unmarshal([]byte(resp.Node.Value), &c.Cert)
}

func (c *Cert) loadCert(ec client.Client) error {
	// create a new keys API
	kapi := client.NewKeysAPI(ec)
	// get it from etcd
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	resp, err := kapi.Get(ctx, c.CertPath(), nil)
	if err != nil {
		return err
	}
	cancelFunc()
	// load the cert to the struct
	c.Cert.Certificate = []byte(resp.Node.Value)
	return nil
}

func (c *Cert) loadKey(ec client.Client) error {
	// create a new keys API
	kapi := client.NewKeysAPI(ec)
	// get it from etcd
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	resp, err := kapi.Get(ctx, c.KeyPath(), nil)
	if err != nil {
		return err
	}
	cancelFunc()
	// load the cert to the struct
	c.Cert.PrivateKey = []byte(resp.Node.Value)
	return nil
}

func (c *Cert) saveCert(ec client.Client) error {
	// create a new keys API
	kapi := client.NewKeysAPI(ec)
	// save it to etcd
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := kapi.Set(ctx, fmt.Sprintf(certKey, c.Cert.Domain), string(c.Cert.Certificate), &client.SetOptions{PrevExist: client.PrevIgnore}); err != nil {
		return err
	}

	cancelFunc()
	return nil
}

func (c *Cert) saveKey(ec client.Client) error {
	// create a new keys API
	kapi := client.NewKeysAPI(ec)
	// save it to etcd
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := kapi.Set(ctx, fmt.Sprintf(keyKey, c.Cert.Domain), string(c.Cert.PrivateKey), &client.SetOptions{PrevExist: client.PrevIgnore}); err != nil {
		return err
	}

	cancelFunc()
	return nil
}

func (c *Cert) saveMeta(ec client.Client) error {
	// create the JSON
	jsonBytes, err := json.Marshal(c.Cert)
	if err != nil {
		return err
	}
	// create a new keys API
	kapi := client.NewKeysAPI(ec)
	// save it to etcd
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := kapi.Set(ctx, fmt.Sprintf(metaKey, c.Cert.Domain), string(jsonBytes), &client.SetOptions{PrevExist: client.PrevIgnore}); err != nil {
		return err
	}

	cancelFunc()
	return nil
}

func (c *Cert) savePem(ec client.Client) error {
	// combine the cert/key
	pem := c.PEM()
	// create a new keys API
	kapi := client.NewKeysAPI(ec)
	// save it to etcd
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := kapi.Set(ctx, fmt.Sprintf(pemKey, c.Cert.Domain), string(pem), &client.SetOptions{PrevExist: client.PrevIgnore}); err != nil {
		return err
	}

	cancelFunc()
	return nil
}

func readCSRFile(filename string) (*x509.CertificateRequest, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	raw := bytes

	// see if we can find a PEM-encoded CSR
	var p *pem.Block
	rest := bytes
	for {
		// decode a PEM block
		p, rest = pem.Decode(rest)

		// did we fail?
		if p == nil {
			break
		}

		// did we get a CSR?
		if p.Type == "CERTIFICATE REQUEST" {
			raw = p.Bytes
		}
	}

	// no PEM-encoded CSR
	// assume we were given a DER-encoded ASN.1 CSR
	// (if this assumption is wrong, parsing these bytes will fail)
	return x509.ParseCertificateRequest(raw)
}
