package legoetcd

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/xenolf/lego/acme"
)

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
			cert, failures = c.ACME.ObtainCertificate(domains, bundle, nil)
		} else {
			// read the CSR
			csr, err = readCSRFile(csrFile)
			if err != nil {
				// we couldn't read the CSR
				failures = map[string]error{"csr": err}
			} else {
				// obtain a certificate for this CSR
				cert, failures = c.ACME.ObtainCertificateForCSR(*csr, bundle)
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
