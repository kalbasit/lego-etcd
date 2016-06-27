package legoetcd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"golang.org/x/net/context"

	"github.com/coreos/etcd/client"
	"github.com/xenolf/lego/acme"
)

const (
	registrationKey = "/lego/accounts/%s/registration"
	cryptoKey       = "/lego/accounts/%s/key"
)

var (
	// ErrUnknowKeyType is returns when the private key stored in etcd is of an
	// unknown type.
	ErrUnknowKeyType = errors.New("unknown private key type")
	// ErrAccountNotExist is returned if the load did not find an account.
	ErrAccountNotExist = errors.New("account does not exist")
	// ErrKeyAlreadyExists is returned when GenerateKey() is called and the key
	// already exists
	ErrKeyAlreadyExists = errors.New("key already exists")
	// ErrAlreadyRegistered is returned when Register() is called and the account
	// is already registered.
	ErrAlreadyRegistered = errors.New("account already registered")
)

// Account implements acme.Account
type Account struct {
	email        string
	registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

// NewAccount returns a new user with the email provided
func NewAccount(email string) *Account {
	return &Account{email: email}
}

// GetEmail returns the email associated with this user.
func (a *Account) GetEmail() string { return a.email }

// GetRegistration returns the server registration
func (a *Account) GetRegistration() *acme.RegistrationResource { return a.registration }

// GetPrivateKey returns the private RSA account key.
func (a *Account) GetPrivateKey() crypto.PrivateKey { return a.key }

// Load loads the key from etcd.
func (a *Account) Load(c client.Client) error {
	// load the registration
	if err := a.LoadRegistration(c); err != nil {
		return err
	}
	// load the key
	if err := a.LoadKey(c); err != nil {
		return err
	}
	return nil
}

// LoadRegistration loads the registration from etcd.
func (a *Account) LoadRegistration(c client.Client) error {
	// create a new keys API
	kapi := client.NewKeysAPI(c)
	// get the registration
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	resp, err := kapi.Get(ctx, fmt.Sprintf(registrationKey, a.email), nil)
	if err != nil {
		return err
	}
	cancelFunc()
	// decode the registration
	a.registration = &acme.RegistrationResource{}
	return json.Unmarshal([]byte(resp.Node.Value), a.registration)
}

// LoadKey loads the key from etcd.
func (a *Account) LoadKey(c client.Client) error {
	// create a new keys API
	kapi := client.NewKeysAPI(c)
	// get the key
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	resp, err := kapi.Get(ctx, fmt.Sprintf(cryptoKey, a.email), nil)
	if err != nil {
		return err
	}
	cancelFunc()
	// decode the key into a keyBlock
	keyBlock, _ := pem.Decode([]byte(resp.Node.Value))
	// cast the key to the correct format and store it in a.key
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		a.key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return err
		}
		return nil
	case "EC PRIVATE KEY":
		a.key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return err
		}
		return nil
	default:
		return ErrUnknowKeyType
	}
}

// Save saves the key into etcd. The caller is responsible to ensure no race
// conditions by grabbing a lock before calling Save().
func (a *Account) Save(c client.Client) error {
	// save the registration
	if a.registration != nil {
		if err := a.saveRegistration(c); err != nil {
			return err
		}
	}
	// save the key
	if a.key != nil {
		if err := a.saveKey(c); err != nil {
			return err
		}
	}
	return nil
}

// GenerateKey generates a new key.
func (a *Account) GenerateKey() error {
	// create a new key
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}
	// save it to the Account struct
	a.key = privateKey
	// return no error
	return nil
}

// Register registers the account with ACME.
func (a *Account) Register(c *acme.Client) error {
	// register the new account
	reg, err := c.Register()
	if err != nil {
		return err
	}
	// save it to the Account struct
	a.registration = &acme.RegistrationResource{}
	*a.registration = *reg
	return nil
}

func (a *Account) saveRegistration(c client.Client) error {
	// create a new keys API
	kapi := client.NewKeysAPI(c)
	// encode the registration as json
	registrationJSON, err := json.Marshal(a.registration)
	if err != nil {
		return err
	}
	// save it to etcd
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := kapi.Set(ctx, fmt.Sprintf(registrationKey, a.email), string(registrationJSON), &client.SetOptions{PrevExist: client.PrevIgnore}); err != nil {
		return err
	}
	cancelFunc()
	return nil
}

func (a *Account) saveKey(c client.Client) error {
	// create a new keys API
	kapi := client.NewKeysAPI(c)
	// encore the key as PEM
	keyBytes, err := x509.MarshalECPrivateKey(a.key.(*ecdsa.PrivateKey))
	if err != nil {
		return err
	}
	pemKey := pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}
	pemBytes := pem.EncodeToMemory(&pemKey)
	// save it to etcd
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := kapi.Set(ctx, fmt.Sprintf(cryptoKey, a.email), string(pemBytes), &client.SetOptions{PrevExist: client.PrevIgnore}); err != nil {
		return err
	}
	cancelFunc()
	return nil
}
