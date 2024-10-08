// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// IngressLister helps list Ingresses.
// All objects returned here must be treated as read-only.
type IngressLister interface {
	// List lists all Ingresses in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.Ingress, err error)
	// Get retrieves the Ingress from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.Ingress, error)
	IngressListerExpansion
}

// ingressLister implements the IngressLister interface.
type ingressLister struct {
	listers.ResourceIndexer[*v1.Ingress]
}

// NewIngressLister returns a new IngressLister.
func NewIngressLister(indexer cache.Indexer) IngressLister {
	return &ingressLister{listers.New[*v1.Ingress](indexer, v1.Resource("ingress"))}
}
