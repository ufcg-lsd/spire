package svidstore

import (
	"strings"

	"github.com/gogo/protobuf/proto"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/spire/proto/spire/agent/svidstore"
	"github.com/spiffe/spire/proto/spire/common"
)

// TODO: refactor it.
// It expects selectors like:
//
// - aws:name:somename
// - aws:arn:asd123
// - aws:kmsid:asd123
// - gcloud:name:somename
func ParseSelectors(selectors []*common.Selector, typ string) map[string]string {
	data := make(map[string]string)
	for _, s := range selectors {
		if s.Type != typ {
			continue
		}

		value := strings.Split(s.Value, ":")
		data[value[0]] = value[1]
	}

	return data
}

// EncodeSecret creates a secrets binary from a 'workload.X509SVIDResponse'
func EncodeSecret(req *svidstore.PutX509SVIDRequest) ([]byte, error) {
	resp := &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{
			{
				SpiffeId:    req.Svid.SpiffeId,
				Bundle:      req.Svid.Bundle,
				X509Svid:    req.Svid.X509Svid,
				X509SvidKey: req.Svid.X509SvidKey,
			},
		},
		FederatedBundles: req.FederatedBundles,
	}
	return proto.Marshal(resp)
}
