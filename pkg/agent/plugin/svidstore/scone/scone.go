package scone

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName                     = "scone_cas_secretsmanager"
	casSessionNameSelecType        = "cas_session_name"
	casSessionHashSelecType        = "cas_session_hash"
	casSessionEndpoint             = "/session"
	noPredHashMsg                  = "No predecessor hash specified albeit session alias used already"
	predNotNeededMsg               = "Predecessor hash specified albeit session alias unused"
	certificatePemType             = "CERTIFICATE"
	privateKeyPemType              = "PRIVATE KEY"
	predecessorPlaceholder         = "${predecessor}"
	svidPlaceholder                = "${svid}"
	svidKeyPlaceholder             = "${svid-key}"
	sessionNameSelectorPlaceholder = "${session-name-selector}"
	sessionHashSelectorPlaceholder = "${session-hash-selector}"
	caTrustBundlePlaceholder       = "${trust-bundle-ca}"
	nameYAMLKey                    = "name:"
)

var (
	svidSessionTemplate             string
	caBundleSessionTemplate         string
	federatedBundlesSessionTemplate string
	sessionNameSVIDPrefix           string
	sessionNameCA                   string
	sessionNameFederatedBundles     string
)

type sconeWorkloadInfo struct {
	CasSessionName string
	CasSessionHash string
}

type casResponseType struct {
	Hash string `json:"hash"`
}

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
	CasAddress                          string `hcl:"cas_address"`
	ClientCertDir                       string `hcl:"cas_client_certificate"`
	ClientKeyDir                        string `hcl:"cas_client_key"`
	PredecessorDir                      string `hcl:"cas_predecessor_dir"`
	SVIDSessionTemplateFile             string `hcl:"svid_session_template_file"`
	CABundleSessionTemplateFile         string `hcl:"ca_bundle_session_template_file"`
	FederatedBundlesSessionTemplateFile string `hcl:"federated_bundles_session_template_file"`
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

// Configure configures the SecretsMangerPlugin.
func (p *SecretsManagerPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &Config{}
	var err error
	if err = hcl.Decode(config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	caSessionTemplateBytes, err := ioutil.ReadFile(config.CABundleSessionTemplateFile)
	if err != nil {
		return &spi.ConfigureResponse{}, errors.New("error in ca_bundle_session_template_file config. " + err.Error())
	}

	federatedBundlesSessionTemplateBytes, err := ioutil.ReadFile(config.FederatedBundlesSessionTemplateFile)
	if err != nil {
		return &spi.ConfigureResponse{}, errors.New("error in federated_bundles_session_template_file config. " + err.Error())
	}

	svidSessionTemplateBytes, nil := ioutil.ReadFile(config.SVIDSessionTemplateFile)
	if err != nil {
		return &spi.ConfigureResponse{}, errors.New("error in svid_session_template_file config. " + err.Error())
	}

	caBundleSessionTemplate = string(caSessionTemplateBytes)
	sessionNameCA, err = getSessionNameFromTemplate(caBundleSessionTemplate)
	if err != nil {
		return &spi.ConfigureResponse{}, err
	}

	federatedBundlesSessionTemplate = string(federatedBundlesSessionTemplateBytes)
	sessionNameFederatedBundles, err = getSessionNameFromTemplate(federatedBundlesSessionTemplate)
	if err != nil {
		return &spi.ConfigureResponse{}, err
	}

	svidSessionTemplate = string(svidSessionTemplateBytes)
	sessionNameSVIDPrefix, err = getSVIDSessionNameFromTemplate(svidSessionTemplate)
	if err != nil {
		return &spi.ConfigureResponse{}, err
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

func getSVIDSessionNameFromTemplate(template string) (string, error) {
	haystack := strings.Split(template, "\n")
	for _, item := range haystack {
		if strings.HasPrefix(item, nameYAMLKey) {
			nameWithPlaceholder := strings.Split(item, nameYAMLKey)[1]
			return strings.Trim(
				strings.Split(nameWithPlaceholder, sessionNameSelectorPlaceholder)[0], " "), nil
		}
	}
	return "", errors.New("cannot find name prefix in template for SVID session")
}

func getSessionNameFromTemplate(template string) (string, error) {
	haystack := strings.Split(template, "\n")
	for _, item := range haystack {
		if strings.HasPrefix(item, nameYAMLKey) {
			return strings.Trim(strings.Split(item, nameYAMLKey)[1], " "), nil
		}
	}
	return "", errors.New("cannot find session name in template")
}

func (p *SecretsManagerPlugin) extractWorkloadInfoFromSelectors(selectors []*common.Selector) (*sconeWorkloadInfo, error) {

	hasSconeSessionName, hasSconeSessionHash := false, false
	var casSessionName string
	var casSessionHash string
	for _, selector := range selectors {
		if selector.GetType() == casSessionNameSelecType {
			casSessionName = selector.GetValue()
			hasSconeSessionName = true
		}
		if selector.GetType() == casSessionHashSelecType {
			casSessionHash = selector.GetValue()
			hasSconeSessionHash = true
		}
	}
	if hasSconeSessionName && hasSconeSessionHash {
		return &sconeWorkloadInfo{CasSessionName: casSessionName, CasSessionHash: casSessionHash}, nil
	}
	if hasSconeSessionName && !hasSconeSessionHash {
		p.log.Warn("Found SGX workload that has a Session Name Selector, but has not Session Hash Selector. SessionName=", casSessionName)
	}
	if !hasSconeSessionName && hasSconeSessionHash {
		p.log.Warn("Found SGX workload that has a Session Hash Selector, but has not Session Name Selector: SessionHash=", casSessionHash)
	}
	return &sconeWorkloadInfo{}, errors.New("can not extract confidential workload info from selectors")
}

// generateSVIDSessionText is an auxiliar func to gerenate the SCONE CAS session expected text format
func (p *SecretsManagerPlugin) generateSVIDSessionText(sconeWorkloadInfo *sconeWorkloadInfo, svid string, privateKey string) string {
	session := strings.ReplaceAll(svidSessionTemplate, predecessorPlaceholder,
		p.readPredecessor(sessionNameSVIDPrefix+sconeWorkloadInfo.CasSessionName))
	session = strings.ReplaceAll(session, svidPlaceholder, pemToSconeInjectionFile(svid))
	session = strings.ReplaceAll(session, svidKeyPlaceholder, pemToSconeInjectionFile(privateKey))
	session = strings.ReplaceAll(session, sessionNameSelectorPlaceholder, sconeWorkloadInfo.CasSessionName)
	session = strings.ReplaceAll(session, sessionHashSelectorPlaceholder, sconeWorkloadInfo.CasSessionHash)

	return session
}

func (p *SecretsManagerPlugin) generateCASessionText(svidCa string) string {
	session := strings.ReplaceAll(caBundleSessionTemplate, predecessorPlaceholder,
		p.readPredecessor(sessionNameCA))
	session = strings.ReplaceAll(session,
		caTrustBundlePlaceholder,
		pemToSconeInjectionFile(svidCa))
	return session
}

func (p *SecretsManagerPlugin) generateFederatedBundlesSessionText(federatedBundles string) string {
	session := strings.ReplaceAll(federatedBundlesSessionTemplate, predecessorPlaceholder,
		p.readPredecessor(sessionNameFederatedBundles))
	session = strings.ReplaceAll(session,
		caTrustBundlePlaceholder,
		pemToSconeInjectionFile(federatedBundles))
	return session
}

func (p *SecretsManagerPlugin) doPostRequest(session string) (*http.Response, error) {
	// Load certificates for connections with CAS API
	// TODO(silvamatteus): check the CA certificate for CAS
	// caCert, err := ioutil.ReadFile("cas_ca.crt")
	// if err != nil {
	//      log.Fatal(err)
	// }
	// caCertPool := x509.NewCertPool()
	// caCertPool.AppendCertsFromPEM(caCerts)
	cert, err := tls.LoadX509KeyPair(p.config.ClientCertDir, p.config.ClientKeyDir)
	if err == nil {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:            nil,
					Certificates:       []tls.Certificate{cert},
					InsecureSkipVerify: true,
				},
			},
		}

		return client.Post(p.config.CasAddress+casSessionEndpoint, "application/text", strings.NewReader(session))
	}
	return &http.Response{}, err
}

func (p *SecretsManagerPlugin) postSessionIntoCAS(session string, sessionName string) error {
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
		if strings.Contains(bodyStr, predNotNeededMsg) {
			p.log.Warn("Predecessor is not needed for session=" + sessionName + ". Clening up predecessor file")
			err := os.Remove(p.config.PredecessorDir + "/" + sessionName)
			if err != nil {
				p.log.Error("Unable to delete predecessor file for session", sessionName, err)
			}
			return errors.New("predecess is not needed")
		}
		if strings.Contains(bodyStr, noPredHashMsg) {
			return errors.New("unknown predecessor hash needed for the session=" + sessionName + "Reconfigure your CAS")
		}

	} else {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		err = json.Unmarshal(body, &casResponse)
		if err != nil {
			p.log.Error("cannot decode JSON response from CAS")
			return err
		}
		p.writePredecessor(sessionName, casResponse.Hash)
		p.log.Info("Saving predecessor hash=" + casResponse.Hash +
			" session_name=" + sessionName + " dir=" + p.config.PredecessorDir)
	}
	defer resp.Body.Close()
	return nil
}

func (p *SecretsManagerPlugin) postSvidAndKeyIntoCAS(svid string, privateKey string, sconeWorkloadInfo *sconeWorkloadInfo) error {
	retrier := retry.NewRetrier(5, time.Second, 5*time.Second)

	err := retrier.Run(func() error {
		session := p.generateSVIDSessionText(sconeWorkloadInfo, svid, privateKey)
		err := p.postSessionIntoCAS(session, sessionNameSVIDPrefix+sconeWorkloadInfo.CasSessionName)
		if err != nil {
			p.log.Error("cannot post SVID and its key into CAS ", err)
		}
		return err
	})
	if err != nil {
		return errors.New("max retries exceeded! Cannot post SVID and its key into CAS " + err.Error())
	}

	return nil
}

func (p *SecretsManagerPlugin) postCABundleIntoCAS(ca string) error {
	retrier := retry.NewRetrier(5, time.Second, 5*time.Second)

	err := retrier.Run(func() error {
		session := p.generateCASessionText(ca)
		err := p.postSessionIntoCAS(session, sessionNameCA)
		if err != nil {
			p.log.Error("cannot post spire CA into CAS ", err)
		}
		return err
	})
	if err != nil {
		return errors.New("max retries exceeded! Cannot post spire CA into CAS " + err.Error())
	}

	return nil
}

func (p *SecretsManagerPlugin) postFederatedBundlesIntoCAS(federatedBundles string) error {
	retrier := retry.NewRetrier(5, time.Second, 5*time.Second)

	err := retrier.Run(func() error {
		session := p.generateFederatedBundlesSessionText(federatedBundles)
		err := p.postSessionIntoCAS(session, sessionNameCA)
		if err != nil {
			p.log.Error("cannot post federated bundles into CAS ", err)
		}
		return err
	})
	if err != nil {
		return errors.New("max retries exceeded! Cannot post federated bundles into CAS " + err.Error())
	}

	return nil
}

// PutX509SVID puts the specified X509-SVID in the configured SCONE Configuration and Attestation Service
func (p *SecretsManagerPlugin) PutX509SVID(ctx context.Context, req *svidstore.PutX509SVIDRequest) (*svidstore.PutX509SVIDResponse, error) {
	sconeWorkloadInfo, err := p.extractWorkloadInfoFromSelectors(req.Selectors)
	if err != nil {
		return &svidstore.PutX509SVIDResponse{}, err
	}

	// Parse SVID
	certificateList, err := x509.ParseCertificates(req.GetSvid().GetX509Svid())
	if err != nil {
		return &svidstore.PutX509SVIDResponse{}, err
	}

	// Parse only the first item of the certificate list (last SVID issued)
	bufPemCert := pem.EncodeToMemory(&pem.Block{Type: certificatePemType, Bytes: certificateList[0].Raw})
	if bufPemCert == nil {

		return &svidstore.PutX509SVIDResponse{}, errors.New("cannot encode SVID to PEM")
	}

	encodedPrivateKey := pem.EncodeToMemory(&pem.Block{Type: privateKeyPemType, Bytes: req.GetSvid().GetX509SvidKey()})
	if encodedPrivateKey == nil {
		return &svidstore.PutX509SVIDResponse{}, errors.New("cannot encode SVID key to pem format")
	}

	err = p.postSvidAndKeyIntoCAS(string(bufPemCert), string(encodedPrivateKey), sconeWorkloadInfo)
	if err != nil {
		return &svidstore.PutX509SVIDResponse{}, err
	}

	// Parse CA Bundle
	bufPemCA, err := caListToBufPem(req.GetSvid().GetBundle())
	if err != nil {
		return &svidstore.PutX509SVIDResponse{}, err
	}

	err = p.postCABundleIntoCAS(bufPemCA)
	if err != nil {
		return &svidstore.PutX509SVIDResponse{}, err
	}

	// Parse Federated Bundles
	bufPemFederatedBundles, err := federatedBundlesToBufPem(req.GetFederatedBundles())
	if err != nil {
		return &svidstore.PutX509SVIDResponse{}, err
	}

	if len(bufPemFederatedBundles) > 0 {
		err = p.postFederatedBundlesIntoCAS(bufPemFederatedBundles)
	}

	return &svidstore.PutX509SVIDResponse{}, nil
}

func caListToBufPem(bundle []byte) (string, error) {
	caList, err := x509.ParseCertificates(bundle)
	if err != nil {
		return "", err
	}

	var bufPemCA bytes.Buffer
	for _, cert := range caList {
		pemBuf := pem.EncodeToMemory(&pem.Block{Type: certificatePemType, Bytes: cert.Raw})
		if pemBuf == nil {
			return "", errors.New("cannot encode CA bundle to PEM")
		}
		bufPemCA.Write(pemBuf)
	}
	return bufPemCA.String(), nil
}

func federatedBundlesToBufPem(federatedBundles map[string][]byte) (string, error) {
	var bufPemCA bytes.Buffer
	for _, bundle := range federatedBundles {
		caList, err := x509.ParseCertificates(bundle)
		if err != nil {
			return "", err
		}

		for _, cert := range caList {
			pemBuf := pem.EncodeToMemory(&pem.Block{Type: certificatePemType, Bytes: cert.Raw})
			if pemBuf == nil {
				return "", errors.New("cannot encode CA bundle to PEM")
			}
			bufPemCA.Write(pemBuf)
		}
	}

	return bufPemCA.String(), nil
}

func pemToSconeInjectionFile(svid string) string {
	return strings.Join(strings.Split(svid, "\n"), "\n        ")
}

func (p *SecretsManagerPlugin) writePredecessor(sessionName string, predecessor string) error {
	if _, err := os.Stat(p.config.PredecessorDir); os.IsNotExist(err) {
		os.Mkdir(p.config.PredecessorDir, 0744)
	}
	err := ioutil.WriteFile(p.config.PredecessorDir+"/"+sessionName, []byte(predecessor), 0644)
	if err != nil {
		p.log.Error("cannot write predecessor for session", err)
	}
	return err
}

func (p *SecretsManagerPlugin) readPredecessor(sessionName string) string {
	predecessor, err := ioutil.ReadFile(p.config.PredecessorDir + "/" + sessionName)
	if err != nil {
		p.log.Warn("cannot read predecessor for session", err)
		return "~"
	}
	return string(predecessor)
}
