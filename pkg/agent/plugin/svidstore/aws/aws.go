package aws

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "aws_secretsmanager"
)

var (
	accessKeyID     = os.Getenv("AWS_ACCESS_KEY_ID")
	secretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	region          = os.Getenv("AWS_REGION")
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
	AccessKeyID      string `hcl:"access_key_id"`
	SecretsAccessKey string `hcl:"secret_access_key"`
	Region           string `hcl:"region"`
}

type SecretsManagerPlugin struct {
	svidstore.UnsafeSVIDStoreServer

	log    hclog.Logger
	config *Config
	mtx    sync.RWMutex
}

func (p *SecretsManagerPlugin) SetLogger(log hclog.Logger) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.log = log
}

// Configure configures the SecretsManagerPlugin.
func (p *SecretsManagerPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &Config{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config

	if config.AccessKeyID != "" {
		accessKeyID = config.AccessKeyID
	}

	if config.Region != "" {
		region = config.Region
	}

	if config.SecretsAccessKey != "" {
		secretAccessKey = config.SecretsAccessKey
	}

	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and other metadata of the plugin.
func (*SecretsManagerPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// PutX509SVID puts the specified X509-SVID in the configured AWS Secrets Manager
func (p *SecretsManagerPlugin) PutX509SVID(ctx context.Context, req *svidstore.PutX509SVIDRequest) (*svidstore.PutX509SVIDResponse, error) {
	// Create client
	sm, err := createSecretManagerClient()
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	data := svidstore.ParseSelectors(req.Selectors, "aws")

	// ARN or name can be used as ID
	name := data["name"]
	secretID := name
	if secretID == "" {
		secretID = data["arn"]
	}

	if secretID == "" {
		return nil, status.Error(codes.InvalidArgument, "secret name or ARN are required")
	}

	// Call DescribeSecret to retrieve the details of the secret
	// and be able to determine if the secret exists
	secretDesc, err := sm.DescribeSecret(&secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretID),
	})
	if aerr, ok := err.(awserr.Error); ok {
		switch aerr.Code() {
		case "ResourceNotFoundException":
			// Secret not found, creating one with provided `name`
			kmsKeyID := data["kmskeyid"]
			resp, err := createSecret(sm, req, name, kmsKeyID)
			if err != nil {
				return nil, err
			}
			p.log.With("version_id", aws.StringValue(resp.VersionId)).With("aws_arn", aws.StringValue(resp.ARN)).Debug("Secret created")

			return &svidstore.PutX509SVIDResponse{}, nil
		default:
			return nil, status.Errorf(codes.Internal, "failed to describe secret: %v", err)
		}
	}

	// Validate that the secret has the 'spire-svid' tag. This tag is used to distinguish the secrets
	// that have SVID information handled by SPIRE
	if ok := validateTag(secretDesc.Tags); !ok {
		return nil, status.Error(codes.InvalidArgument, "secret does not contain the 'spire-svid' tag")
	}

	// Encode the secret from a 'workload.X509SVIDResponse'
	secretBinary, err := svidstore.EncodeSecret(req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create svid response: %v", err)
	}
	putResp, err := sm.PutSecretValue(&secretsmanager.PutSecretValueInput{
		SecretId:     secretDesc.ARN,
		SecretBinary: secretBinary,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to put secret: %v", err)
	}

	p.log.With("version_id", aws.StringValue(putResp.VersionId)).With("aws_arn", aws.StringValue(putResp.ARN)).Debug("Secret value updated")

	return &svidstore.PutX509SVIDResponse{}, nil
}

func createSecret(sm *secretsmanager.SecretsManager, req *svidstore.PutX509SVIDRequest, name string, kmsKeyID string) (*secretsmanager.CreateSecretOutput, error) {
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name selector is required to create a Secret")
	}

	secretBinary, err := svidstore.EncodeSecret(req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create svid response: %v", err)
	}

	resp, err := sm.CreateSecret(&secretsmanager.CreateSecretInput{
		Name:     aws.String(name),
		KmsKeyId: aws.String(kmsKeyID),
		Tags: []*secretsmanager.Tag{
			{
				Key:   aws.String("spire-svid"),
				Value: aws.String("true"),
			},
		},
		SecretBinary: secretBinary,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secret: %v", err)
	}

	return resp, nil
}

// validateTag expects that "spire-svid" tag is provided
func validateTag(tags []*secretsmanager.Tag) bool {
	for _, tag := range tags {
		if aws.StringValue(tag.Key) == "spire-svid" && aws.StringValue(tag.Value) == "true" {
			return true
		}
	}

	return false
}

func createSecretManagerClient() (*secretsmanager.SecretsManager, error) {
	var awsConf *aws.Config
	if secretAccessKey != "" && accessKeyID != "" {
		creds := credentials.NewStaticCredentials(accessKeyID, secretAccessKey, "")
		awsConf = &aws.Config{Credentials: creds, Region: aws.String(region)}
	} else {
		awsConf = &aws.Config{Region: aws.String(region)}
	}
	sess, err := session.NewSession(awsConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	return secretsmanager.New(sess), nil
}
