package catalog

import (
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore/awssecretsmanager"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore/gcpsecretmanager"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore/sconecas"
	"github.com/spiffe/spire/pkg/common/catalog"
)

type svidStoreRepository struct {
	svidstore.Repository
}

func (repo *svidStoreRepository) Binder() interface{} {
	return repo.SetSVIDStore
}

func (repo *svidStoreRepository) Constraints() catalog.Constraints {
	return catalog.ZeroOrMore()
}

func (repo *svidStoreRepository) Versions() []catalog.Version {
	return []catalog.Version{svidStoreV1{}, svidStoreV1Unofficial{}}
}

func (repo *svidStoreRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		awssecretsmanager.BuiltIn(),
		gcpsecretmanager.BuiltIn(),
		sconecas.BuiltIn(),
	}
}

type svidStoreV1 struct{}

func (svidStoreV1) New() catalog.Facade { return new(svidstore.V1) }
func (svidStoreV1) Deprecated() bool    { return false }

type svidStoreV1Unofficial struct{}

func (svidStoreV1Unofficial) New() catalog.Facade { return new(svidstore.V1Unofficial) }
func (svidStoreV1Unofficial) Deprecated() bool    { return true }
