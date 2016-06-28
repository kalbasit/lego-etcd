package service

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/coreos/etcd/client"
	"golang.org/x/net/context"
)

// ErrLockExists is returned if unable to grab a lock.
var ErrLockExists = errors.New("was unable to grab a lock, lock already exists")

// Lock places a lock at the provided path in etcd.
func (s *Service) Lock(c client.Client, path string) error {
	// create a new keys API
	kapi := client.NewKeysAPI(c)
	// save it to etcd
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := kapi.Set(ctx, path, s.lockContents(), &client.SetOptions{PrevExist: client.PrevNoExist, TTL: 1 * time.Hour}); err != nil {
		if err.(client.Error).Code == client.ErrorCodeNodeExist {
			return ErrLockExists
		}
		return err
	}
	cancelFunc()
	return nil
}

// Unlock removes the lock at the provided path from etcd
func (s *Service) Unlock(c client.Client, path string) error {
	// create a new keys API
	kapi := client.NewKeysAPI(c)
	// save it to etcd
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := kapi.Delete(ctx, path, &client.DeleteOptions{PrevValue: s.lockContents()}); err != nil {
		return err
	}
	cancelFunc()
	return nil
}

// WaitForLockDeletion is a blocking call that will wait until the lock is
// unlocked.
func (s *Service) WaitForLockDeletion(c client.Client, path string) error {
	// create a new keys API
	kapi := client.NewKeysAPI(c)
	// watch the key for deletion
	for {
		w := kapi.Watcher(path, nil)
		resp, err := w.Next(context.Background())
		if err != nil {
			// the key was already removed, just return
			if client.IsKeyNotFound(err) {
				return nil
			}
			return err
		}
		// wait for a delete action
		if resp.Action == "delete" {
			return nil
		}
	}
}

func (s *Service) lockContents() string {
	host, err := os.Hostname()
	if err != nil {
		log.Printf("error fetching the hostname: %s", err)
		host = "n/a"
	}
	return fmt.Sprintf("%s-%d", host, os.Getpid())
}
