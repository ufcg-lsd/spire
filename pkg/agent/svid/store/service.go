package store

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/manager/pipe"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
)

type Service interface {
	// Run start the store service. It will block until the context is cancelled.
	Run(ctx context.Context) error
}

type Config struct {
	Log     logrus.FieldLogger
	PipeOut pipe.Out
	Catalog catalog.Catalog
}

const (
	typeSelector = "type"
)

func New(c Config) Service {
	return &store{
		c: &c,
	}
}

type store struct {
	c *Config
}

func (p *store) Run(ctx context.Context) error {
	err := util.RunTasks(ctx,
		p.run,
	)

	switch {
	case err == nil || err == context.Canceled:
		p.c.Log.Info("Service stopped")
		return nil
	default:
		p.c.Log.WithError(err).Error("Service crashed")
		return err
	}
}

func (p *store) run(ctx context.Context) error {
	log := p.c.Log

	// Get all configured SVID stores and create a map with them
	// keyed by the plugin name
	svidStores := make(map[string]svidstore.SVIDStore)
	for _, pp := range p.c.Catalog.GetSVIDStores() {
		svidStores[pp.Name()] = pp
	}

	// This is a defensive check. This code is only reachable when there is
	// at least one SVID Publisher plugin
	if len(svidStores) == 0 {
		return errors.New("no SVID store provided")
	}

	for {
		select {
		case update := <-p.c.PipeOut.GetUpdate():
			log := log.WithField(telemetry.RegistrationID, update.Entry.EntryId)
			// Get SVID store name from the selectors of the entry
			pluginName, err := getPluginName(update.Entry.Selectors)
			if err != nil {
				log.WithError(err).Debugf("Unable to get plugin name from selectors")
				continue
			}

			log = log.WithField("plugin_name", pluginName)

			svidStore, ok := svidStores[pluginName]
			if !ok {
				log.Warn("no SVID store found for entry")
				continue
			}

			req, err := parseUpdate(update)
			if err != nil {
				log.WithError(err).Error("Failed to create request from update")
				continue
			}

			if _, err := svidStore.PutX509SVID(ctx, req); err != nil {
				log.Errorf("Failed to put X509-SVID to %q: %v", pluginName, err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func getPluginName(selectors []*common.Selector) (string, error) {
	for _, selector := range selectors {
		// selector "svidstore:type:$PLUGIN_NAME" is expected
		if selector.Type == strings.ToLower(svidstore.Type) {
			splitted := strings.SplitN(selector.Value, ":", 2)
			if len(splitted) > 1 && splitted[0] == typeSelector {
				return splitted[1], nil
			}
		}
	}
	return "", errors.New("store information not found in selectors")
}

// parseUpdate parses an SVID Update into a *svidstore.PutX509SVIDRequest request
func parseUpdate(update *pipe.SVIDUpdate) (*svidstore.PutX509SVIDRequest, error) {
	federatedBundles := make(map[string][]byte)
	for id, bundle := range update.FederatedBundles {
		federatedBundles[id] = marshalBundle(bundle)
	}

	keyData, err := x509.MarshalPKCS8PrivateKey(update.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key for entry ID %q: %v", update.Entry.EntryId, err)
	}

	return &svidstore.PutX509SVIDRequest{
		Selectors: update.Entry.Selectors,
		Svid: &svidstore.X509SVID{
			SpiffeId:    update.Entry.SpiffeId,
			Bundle:      marshalBundle(update.Bundle),
			X509SvidKey: keyData,
			X509Svid:    x509util.DERFromCertificates(update.SVID),
		},
		FederatedBundles: federatedBundles,
	}, nil
}

func marshalBundle(b *bundleutil.Bundle) []byte {
	var bundle []byte
	for _, b := range b.RootCAs() {
		bundle = append(bundle, b.Raw...)
	}

	return bundle
}
