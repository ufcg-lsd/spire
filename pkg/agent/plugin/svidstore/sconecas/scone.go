package sconecas

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/flowchartsman/retry"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	svidstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/svidstore/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName                             = "sconecas_sessionmanager"
	casSessionEndpoint                     = "/session"
	noPredHashMsg                          = "Session already exists, please specify predecessor hash"
	predecessorPlaceholder                 = "<\\predecessor>"
	svidPlaceholder                        = "<\\svid>"
	svidIntermediatesPlaceholder           = "<\\svid-intermediates>"
	svidKeyPlaceholder                     = "<\\svid-key>"
	sessionNameSelectorPlaceholder         = "<\\session-name-selector>"
	sessionHashSelectorPlaceholder         = "<\\session-hash-selector>"
	caTrustBundlePlaceholder               = "<\\trust-bundle>"
	trustBundleSessionNamePlaceholder      = "<\\trust-bundle-session-name>"
	federatedBundlesPlaceholder            = "<\\federated-bundles>"
	federatedBundlesSessionNamePlaceholder = "<\\fed-bundles-session-name>"
	nameYAMLKey                            = "name:"
	endCertificateStr                      = "-----END CERTIFICATE-----\n"
)

// BuiltIn returns the a new plugin instance
func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *SessionManagerPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		svidstorev1.SVIDStorePluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// New creates a new plugin instance
func New() *SessionManagerPlugin {
	p := &SessionManagerPlugin{}
	p.templateInfo = &templateInfo{}
	return p
}

// Config holds the plugin configuration
type Config struct {
	CasConnectionStr                    string `hcl:"cas_connection_string"`
	ClientCertDir                       string `hcl:"cas_client_certificate"`
	ClientKeyDir                        string `hcl:"cas_client_key"`
	PredecessorDir                      string `hcl:"cas_predecessor_dir"`
	SVIDSessionTemplateFile             string `hcl:"svid_session_template_file"`
	CABundleSessionTemplateFile         string `hcl:"bundle_session_template_file"`
	FederatedBundlesSessionTemplateFile string `hcl:"federated_bundles_session_template_file"`
	CasTrustAnchorCertificate           string `hcl:"trust_anchor_certificate"`
	InsecureSkipSVerifyTLS              bool   `hcl:"insecure_skip_verify_tls"`
}

type templateInfo struct {
	svidSessionTemplate             string
	caBundleSessionTemplate         string
	federatedBundlesSessionTemplate string
	sessionSvidNameTemplate         string
	bundleSessionName               string
	federatedBundlesSessionName     string
}

type casResponseType struct {
	Hash string `json:"hash"`
}

// SessionManagerPlugin type
type SessionManagerPlugin struct {
	svidstorev1.UnsafeSVIDStoreServer
	configv1.UnsafeConfigServer

	log          hclog.Logger
	mtx          sync.RWMutex
	config       *Config
	templateInfo *templateInfo
}

type sconeWorkloadInfo struct {
	CasSessionName         string
	CasSessionHash         string
	TrustBundleSessionName string
	FedBundlesSessionName  string
}

// SetLogger sets a new logger for SessionManagerPlugin
func (p *SessionManagerPlugin) SetLogger(log hclog.Logger) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.log = log
}

// Configure configures the SessionManagerPlugin
func (p *SessionManagerPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	config := &Config{}
	var err error
	if err = hcl.Decode(config, req.GetHclConfiguration()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	caSessionTemplateBytes, err := ioutil.ReadFile(config.CABundleSessionTemplateFile)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to parse bundle session template: %v", err)
	}

	federatedBundlesSessionTemplateBytes, err := ioutil.ReadFile(config.FederatedBundlesSessionTemplateFile)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to parse federated bundles session template: %v", err)
	}

	svidSessionTemplateBytes, err := ioutil.ReadFile(config.SVIDSessionTemplateFile)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to parse svid session template: %v", err)
	}

	p.templateInfo.caBundleSessionTemplate = string(caSessionTemplateBytes)
	p.templateInfo.bundleSessionName, err = p.getSessionNameFromTemplate(p.templateInfo.caBundleSessionTemplate)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to get ca session name from template: %v", err)
	}

	p.templateInfo.federatedBundlesSessionTemplate = string(federatedBundlesSessionTemplateBytes)
	p.templateInfo.federatedBundlesSessionName, err = p.getSessionNameFromTemplate(p.templateInfo.federatedBundlesSessionTemplate)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to get federated bundles session name from template: %v", err)
	}

	p.templateInfo.svidSessionTemplate = string(svidSessionTemplateBytes)
	p.templateInfo.sessionSvidNameTemplate, err = p.getSessionNameFromTemplate(p.templateInfo.svidSessionTemplate)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to svid session prefix name from template: %v", err)
	}

	err = os.MkdirAll(config.PredecessorDir, 0700)
	if err != nil {
		p.log.With("os_error", err).Error("cannot create predecessors directory")
		return nil, status.Errorf(codes.Internal, "cannot create predecessors directory: %v", err)
	}

	if config.InsecureSkipSVerifyTLS {
		p.log.Warn("insecure_skip_verify_tls enabled. The plugin " +
			pluginName + " will trust any CAS. Do not use this config in production!")
	}
	p.config = config
	return &configv1.ConfigureResponse{}, nil
}

// PutX509SVID puts the svid into the configured CAS
func (p *SessionManagerPlugin) PutX509SVID(ctx context.Context, req *svidstorev1.PutX509SVIDRequest) (*svidstorev1.PutX509SVIDResponse, error) {
	sconeWorkloadInfo, err := p.selectorsFromMetadata(req.GetMetadata())
	if err != nil {
		return &svidstorev1.PutX509SVIDResponse{}, status.Errorf(codes.InvalidArgument, "cannot extract workload info from selectors: %v", err)
	}

	svidData, err := svidstore.SecretFromProto(req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to parse svid data: %v", err)
	}

	err = p.postSvidIntoCAS(svidData.X509SVID, svidData.X509SVIDKey, sconeWorkloadInfo)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "unable to post svid into cas: %v", err)
	}

	err = p.postBundleIntoCAS(svidData.Bundle, sconeWorkloadInfo)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "unable to post bundle into cas: %v", err)
	}

	if len(svidData.FederatedBundles) > 0 {
		err = p.postFederatedBundlesIntoCAS(svidData.FederatedBundles, sconeWorkloadInfo)
	}
	return &svidstorev1.PutX509SVIDResponse{}, err
}

// DeleteX509SVID does nothing in case of SCONE CAS once there is no delete operation for sessions
func (p *SessionManagerPlugin) DeleteX509SVID(ctx context.Context, req *svidstorev1.DeleteX509SVIDRequest) (*svidstorev1.DeleteX509SVIDResponse, error) {
	return &svidstorev1.DeleteX509SVIDResponse{}, nil
}

func (p *SessionManagerPlugin) postSvidIntoCAS(svidChain string, privKey string, workloadInfo *sconeWorkloadInfo) error {
	retrier := retry.NewRetrier(5, time.Second, 5*time.Second)

	err := retrier.Run(func() error {
		sessionName := strings.ReplaceAll(p.templateInfo.sessionSvidNameTemplate, sessionNameSelectorPlaceholder, workloadInfo.CasSessionName)
		session := p.generateSVIDSessionText(svidChain, privKey, workloadInfo, sessionName)
		err := p.postSessionIntoCAS(session, sessionName)
		if err != nil {
			p.log.Error("cannot post SVID and its key into CAS ", err.Error())
		}
		return err
	})
	if err != nil {
		return errors.New("max retries exceeded! Cannot post SVID and its key into CAS " + err.Error())
	}

	return nil
}

func (p *SessionManagerPlugin) postBundleIntoCAS(bundle string, workloadInfo *sconeWorkloadInfo) error {
	retrier := retry.NewRetrier(5, time.Second, 5*time.Second)

	err := retrier.Run(func() error {
		session, sessionName := p.generateCASessionText(bundle, workloadInfo)
		err := p.postSessionIntoCAS(session, sessionName)
		if err != nil {
			p.log.Error("cannot post bundle into CAS ", err.Error())
		}
		return err
	})
	if err != nil {
		return errors.New("max retries exceeded! Cannot post bundle CA into CAS " + err.Error())
	}

	return nil
}

func (p *SessionManagerPlugin) postFederatedBundlesIntoCAS(fedBundlesMap map[string]string, workloadInfo *sconeWorkloadInfo) error {
	bundles := bundleMapToStr(fedBundlesMap)
	retrier := retry.NewRetrier(5, time.Second, 5*time.Second)

	err := retrier.Run(func() error {
		session, sessionName := p.generateFederatedBundlesSessionText(bundles, workloadInfo)
		err := p.postSessionIntoCAS(session, sessionName)
		if err != nil {
			p.log.Error("cannot post federated bundles into CAS ", err.Error())
		}
		return err
	})
	if err != nil {
		return errors.New("max retries exceeded! Cannot post federated bundles into CAS " + err.Error())
	}

	return nil
}

func (p *SessionManagerPlugin) postSessionIntoCAS(session string, sessionName string) error {
	p.log.Info("Posting Session:", session)
	resp, err := p.doPostRequest(session)
	if err != nil {
		return err
	}
	casResponse := casResponseType{}
	if resp.StatusCode != http.StatusCreated {
		p.log.Error("cannot post SVID into CAS. Response status code =", resp.Status)
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		bodyStr := string(body)

		if resp.StatusCode == http.StatusNotFound {
			p.log.Warn("Predecessor may be not needed for session="+sessionName+". Cleaning up predecessor file to try again.",
				"The Store SVID plugin may not recover from this failure")
			err := os.Remove(p.config.PredecessorDir + "/" + sessionName)
			if err != nil {
				p.log.Error("unable to delete predecessor file for session", sessionName, err.Error())
			}
			return errors.New("error=" + bodyStr)
		}
		if strings.Contains(bodyStr, noPredHashMsg) {
			return errors.New("unknown predecessor hash needed for the session=" + sessionName + " Reconfigure your CAS")
		}

		return errors.New("error=" + bodyStr)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(body, &casResponse)
	if err != nil {
		p.log.Error("cannot decode JSON response from CAS")
		return err
	}
	p.log.Info("Saving predecessor hash=" + casResponse.Hash +
		" session_name=" + sessionName + " dir=" + p.config.PredecessorDir)
	err = p.writePredecessor(sessionName, casResponse.Hash)
	if err != nil {
		p.log.With("session", sessionName, "error", err).Error("cannot write predecessor for session")
	}

	defer resp.Body.Close()
	return nil
}

func (p *SessionManagerPlugin) doPostRequest(session string) (*http.Response, error) {
	// Load trust anchor certificate for connections with CAS
	// It will ensure that the plugin is talking with an attested CAS instance
	trustAnchorCert, err := ioutil.ReadFile(p.config.CasTrustAnchorCertificate)
	if err != nil {
		p.log.Error("cannot read CAS trust anchor certificate")
	}
	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(trustAnchorCert)
	if !ok {
		return &http.Response{}, errors.New("cannot append append trust anchor certificate to CA pool")
	}
	cert, err := tls.LoadX509KeyPair(p.config.ClientCertDir, p.config.ClientKeyDir)
	if err == nil {
		client := &http.Client{
			Transport: &http.Transport{
				// #nosec
				TLSClientConfig: &tls.Config{
					RootCAs:            caCertPool,
					InsecureSkipVerify: p.config.InsecureSkipSVerifyTLS,
					Certificates:       []tls.Certificate{cert},
				},
			},
		}

		return client.Post(p.config.CasConnectionStr+casSessionEndpoint, "application/text", strings.NewReader(session))
	}
	return &http.Response{}, err
}

func (p *SessionManagerPlugin) generateCASessionText(svidCa string, workloadInfo *sconeWorkloadInfo) (string, string) {
	fullSessionName := strings.ReplaceAll(p.templateInfo.bundleSessionName,
		trustBundleSessionNamePlaceholder, workloadInfo.TrustBundleSessionName)
	session := strings.ReplaceAll(p.templateInfo.caBundleSessionTemplate,
		predecessorPlaceholder,
		p.readPredecessor(fullSessionName))
	session = strings.ReplaceAll(session, trustBundleSessionNamePlaceholder,
		workloadInfo.TrustBundleSessionName)
	session = strings.ReplaceAll(session,
		caTrustBundlePlaceholder,
		pemToSconeInjectionFile(svidCa))
	return session, fullSessionName
}

func (p *SessionManagerPlugin) generateFederatedBundlesSessionText(federatedBundles string, workloadInfo *sconeWorkloadInfo) (string, string) {
	fullSessionName := strings.ReplaceAll(p.templateInfo.federatedBundlesSessionName,
		federatedBundlesSessionNamePlaceholder, workloadInfo.FedBundlesSessionName)
	session := strings.ReplaceAll(p.templateInfo.federatedBundlesSessionTemplate, predecessorPlaceholder,
		p.readPredecessor(fullSessionName))
	session = strings.ReplaceAll(session, federatedBundlesSessionNamePlaceholder,
		workloadInfo.FedBundlesSessionName)
	session = strings.ReplaceAll(session,
		federatedBundlesPlaceholder,
		pemToSconeInjectionFile(federatedBundles))
	return session, fullSessionName
}

func (p *SessionManagerPlugin) generateSVIDSessionText(svidChain string, privKey string, workloadInfo *sconeWorkloadInfo, sessionName string) string {
	svidChainSplitted := strings.SplitN(svidChain, endCertificateStr, 2)
	svid := svidChainSplitted[0] + endCertificateStr
	intermediates := svidChainSplitted[1]

	session := strings.ReplaceAll(p.templateInfo.svidSessionTemplate, predecessorPlaceholder, p.readPredecessor(sessionName))
	session = strings.ReplaceAll(session, svidPlaceholder, pemToSconeInjectionFile(svid))
	session = strings.ReplaceAll(session, svidIntermediatesPlaceholder, pemToSconeInjectionFile(intermediates))
	session = strings.ReplaceAll(session, svidKeyPlaceholder, pemToSconeInjectionFile(privKey))
	session = strings.ReplaceAll(session, sessionNameSelectorPlaceholder, workloadInfo.CasSessionName)
	session = strings.ReplaceAll(session, sessionHashSelectorPlaceholder, workloadInfo.CasSessionHash)

	return session
}

func (p *SessionManagerPlugin) getSessionNameFromTemplate(template string) (string, error) {
	haystack := strings.Split(template, "\n")
	for _, item := range haystack {
		if strings.HasPrefix(item, nameYAMLKey) {
			return strings.Trim(strings.Split(item, nameYAMLKey)[1], " "), nil
		}
	}
	return "", errors.New("cannot find session name in template")
}

func (p *SessionManagerPlugin) selectorsFromMetadata(metadata []string) (*sconeWorkloadInfo, error) {
	data, err := svidstore.ParseMetadata(metadata)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse etadata: %v", err)
	}

	workloadInfo := &sconeWorkloadInfo{
		CasSessionName:         data["session_name"],
		CasSessionHash:         data["session_hash"],
		TrustBundleSessionName: data["trust_bundle_session_name"],
		FedBundlesSessionName:  data["fed_bundles_session_name"],
	}

	if workloadInfo.CasSessionHash == "" || workloadInfo.CasSessionName == "" {
		return nil, errors.New("selectors session_name and session_hash required")
	}

	return workloadInfo, nil
}
func (p *SessionManagerPlugin) writePredecessor(sessionName string, predecessor string) error {
	lastSessionSep := strings.LastIndex(sessionName, "/")
	if lastSessionSep != -1 {
		if _, err := os.Stat(p.config.PredecessorDir + "/" + sessionName[:lastSessionSep]); os.IsNotExist(err) {
			err := os.MkdirAll(p.config.PredecessorDir+"/"+sessionName[:lastSessionSep], 0744)
			if err != nil {
				p.log.Error("cannot create directory. ", err.Error())
				return err
			}
		}
	}
	return ioutil.WriteFile(p.config.PredecessorDir+"/"+sessionName, []byte(predecessor), 0600)
}

func (p *SessionManagerPlugin) readPredecessor(sessionName string) string {
	predecessor, err := ioutil.ReadFile(p.config.PredecessorDir + "/" + sessionName)
	if err != nil {
		p.log.Warn("cannot read predecessor for session ", err.Error())
		return "~"
	}
	return string(predecessor)
}

func pemToSconeInjectionFile(svid string) string {
	return strings.Join(strings.Split(svid, "\n"), "\n        ")
}

func bundleMapToStr(m map[string]string) string {
	var bundles string
	for _, v := range m {
		bundles += v
	}
	return bundles
}
