// TODO: this has not been tested yet
package gcloud

import (
	"context"
	"sync"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/api/option"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "gcloud_secretsmanager"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *SecretsManagerPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, svidstore.PluginServer(p))
}

func New() *SecretsManagerPlugin {
	return &SecretsManagerPlugin{}
}

type Config struct {
	ServiceAccountFile string `hcl:"service_account_file"`
}

type SecretsManagerPlugin struct {
	log    hclog.Logger
	config *Config
	mtx    sync.RWMutex
}

func (p *SecretsManagerPlugin) SetLogger(log hclog.Logger) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.log = log
}

// Configure configures the SecretsMangerPlugin.
func (p *SecretsManagerPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &Config{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config

	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and other metadata of the plugin.
func (*SecretsManagerPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// PutX509SVID puts the specified X509-SVID in the configured Google Cloud Secrets Manager
func (p *SecretsManagerPlugin) PutX509SVID(ctx context.Context, req *svidstore.PutX509SVIDRequest) (*svidstore.PutX509SVIDResponse, error) {
	var opts []option.ClientOption
	if p.config.ServiceAccountFile != "" {
		opts = append(opts, option.WithCredentialsFile(p.config.ServiceAccountFile))
	}

	// Create client
	client, err := secretmanager.NewClient(ctx, opts...)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secretmanager client: %v", err)
	}

	data := svidstore.ParseSelectors(req.Selectors, "gcloud")
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	name, ok := data["name"]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "selector name is required")
	}

	// Describe secret using name or ARN, to verify it exists
	secretDesc, err := client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{
		Name: name,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get secret: %v", err)
	}

	// Validate that Secrets has 'spire-svid' label, it is to make users easy to found what secrets are
	// expected to be updated by SPIRE
	if ok := validateLabels(secretDesc.Labels); !ok {
		return nil, status.Error(codes.InvalidArgument, "secrets that not contains 'spire-svid' tag")
	}

	// Encode the secret from a 'workload.X509SVIDResponse'
	secretBinary, err := svidstore.EncodeSecret(req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create svid response: %v", err)
	}
	resp, err := client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: secretDesc.Name,
		Payload: &secretmanagerpb.SecretPayload{
			Data: secretBinary,
		},
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "faied to add version: %v", err)
	}

	p.log.With("state", resp.State).With("name", resp.Name).Debug("Secret payload updated")

	return &svidstore.PutX509SVIDResponse{}, nil
}

func validateLabels(labels map[string]string) bool {
	spireLabel, ok := labels["spire-svid"]
	if !ok || spireLabel != "true" {
		return false
	}
	return true
}
