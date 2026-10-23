package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"github.com/cicada-ai/cicada/internal/control"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/store"
)

func nativeHubTLSConfig(config control.Config, profile *hubtransport.Profile) *tls.Config {
	cfg := profile.TLSConfig()
	get := cfg.GetCertificate
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// A TLS handshake can outlive HTTP shutdown. Its own shared restore
		// guard keeps deferred leaf renewal serialized against offline backup.
		lease, err := store.AcquireStateStartup(config.StateDir)
		if err != nil {
			return nil, err
		}
		defer lease.Close()
		return get(hello)
	}
	return cfg
}

func nativeHubIdentity(setup *store.HubOwnerSetup, ids hubidentity.Set) wire.HubIdentity {
	return wire.HubIdentity{Contract: "android-hub-v1", HubID: setup.HubID, Public: ids.ClientControl.Public(), KeyVersion: 1, Suite: "ML-KEM-768+ML-DSA-65+AES-256-GCM"}
}

// Historical issuers retain their pre-native compatibility initialization.
// A native pin or even an interrupted profile changes this to strict retained
// identity loading before any issuer constructor can create missing keys.
func hubIssuerIdentities(config control.Config, db *store.Store) (hubidentity.Set, error) {
	pinned, err := db.HubNativeTLSDescriptor()
	if err != nil {
		return hubidentity.Set{}, err
	}
	present, err := hubtransport.ProfilePresent(config.StateDir)
	if err != nil {
		return hubidentity.Set{}, err
	}
	if present || pinned != "" {
		return existingHubNodeIdentities(config)
	}
	return hubidentity.LoadOrCreate(config.StateDir, config.IdentityFile)
}

func initializeHubNativeTLS(config control.Config, db *store.Store, setup *store.HubOwnerSetup, ids hubidentity.Set) (*hubtransport.Profile, error) {
	pinned, err := db.HubNativeTLSDescriptor()
	if err != nil {
		return nil, err
	}
	p, err := hubtransport.InitializeProfile(config.StateDir, ids.ClientControl, nativeHubIdentity(setup, ids), ids.NodeControl.Public(), setup.Origin, pinned)
	if err != nil {
		return nil, err
	}
	if err = db.BindHubNativeTLSLocal(p.DescriptorText()); err != nil {
		return nil, err
	}
	return p, nil
}

func loadHubNativeTLS(config control.Config, db *store.Store, ids hubidentity.Set) (*hubtransport.Profile, error) {
	setup, err := db.GetHubOwnerSetup()
	if err != nil || setup == nil || setup.State != store.HubOwnerReady {
		return nil, hubtransport.ErrInvalid
	}
	pinned, err := db.HubNativeTLSDescriptor()
	if err != nil {
		return nil, err
	}
	d, err := hubtransport.DecodeDescriptor(pinned)
	if err != nil || d.Claims.Origin != setup.Origin || !reflect.DeepEqual(d.Claims.Hub, nativeHubIdentity(setup, ids)) || !reflect.DeepEqual(d.Claims.NodeControl, ids.NodeControl.Public()) {
		return nil, hubtransport.ErrInvalid
	}
	return hubtransport.LoadProfile(config.StateDir, pinned)
}

func hubNativeTLSCommand(args []string, output io.Writer, initialize bool) error {
	flags := flag.NewFlagSet("hub native TLS", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	state := flags.String("state-dir", "", "configured Hub StateDir")
	descriptorFile := flags.String("descriptor-file", "", "new public native TLS descriptor file")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || *descriptorFile == "" || output == nil {
		return errors.New("usage: cicada hub native-tls-init|connection-export --descriptor-file NEW_FILE [--state-dir DIR]")
	}
	config := hubControlConfig(*state, "")
	lease, err := store.AcquireStateStartup(config.StateDir)
	if err != nil {
		return err
	}
	defer lease.Close()
	ids, err := existingHubNodeIdentities(config)
	if err != nil {
		return err
	}
	db, err := store.New(filepath.Join(config.StateDir, "cicada.sqlite3"))
	if err != nil {
		return err
	}
	defer db.Close()
	var profile *hubtransport.Profile
	if initialize {
		setup, err := db.GetHubOwnerSetup()
		if err != nil || setup == nil || setup.State != store.HubOwnerReady {
			return hubtransport.ErrInvalid
		}
		profile, err = initializeHubNativeTLS(config, db, setup, ids)
		if err != nil {
			return err
		}
	} else {
		profile, err = loadHubNativeTLS(config, db, ids)
		if err != nil {
			return err
		}
	}
	if err = writePublicExclusiveOrSame(*descriptorFile, []byte(profile.DescriptorText()+"\n")); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(map[string]string{"state": "HUB_NATIVE_TLS_READY", "descriptor_file": *descriptorFile})
}

// A permanent Store pin and even an interrupted profile directory forbid an
// implicit plaintext startup. Old installations without either retain the old
// behavior; an explicit operator legacy selector is separate from fallback.
func checkHubNativeTLSMode(config control.Config, native, legacy bool) error {
	if native && legacy {
		return errors.New("native TLS and explicit legacy HTTP cannot be combined")
	}
	present, err := hubtransport.ProfilePresent(config.StateDir)
	if err != nil {
		return err
	}
	dbPath := filepath.Join(config.StateDir, "cicada.sqlite3")
	_, err = os.Lstat(dbPath)
	if errors.Is(err, os.ErrNotExist) {
		if native || present {
			return errors.New("native TLS requires a completed existing Hub setup and profile")
		}
		return nil
	}
	if err != nil {
		return err
	}
	lease, err := store.AcquireStateStartup(config.StateDir)
	if err != nil {
		return err
	}
	defer lease.Close()
	db, err := store.New(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	pinned, err := db.HubNativeTLSDescriptor()
	if err != nil {
		return err
	}
	if present || pinned != "" {
		ids, e := existingHubNodeIdentities(config)
		if e != nil {
			return e
		}
		if pinned != "" {
			setup, e := db.GetHubOwnerSetup()
			if e != nil || setup == nil {
				return hubtransport.ErrInvalid
			}
			d, e := hubtransport.DecodeDescriptor(pinned)
			if e != nil || d.Claims.Origin != setup.Origin || !reflect.DeepEqual(d.Claims.Hub, nativeHubIdentity(setup, ids)) || !reflect.DeepEqual(d.Claims.NodeControl, ids.NodeControl.Public()) {
				return hubtransport.ErrInvalid
			}
		}
	}
	if native && (pinned == "" || !present) {
		return errors.New("native TLS profile is unavailable; keys were not regenerated")
	}
	if !native && !legacy && (present || pinned != "") {
		return errors.New("this Hub requires --native-tls; explicit --legacy-http is needed for operator-requested legacy mode")
	}
	return nil
}
