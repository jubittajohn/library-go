// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	v1 "github.com/openshift/api/operator/v1"
	operatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeClusterCSIDrivers implements ClusterCSIDriverInterface
type FakeClusterCSIDrivers struct {
	Fake *FakeOperatorV1
}

var clustercsidriversResource = v1.SchemeGroupVersion.WithResource("clustercsidrivers")

var clustercsidriversKind = v1.SchemeGroupVersion.WithKind("ClusterCSIDriver")

// Get takes name of the clusterCSIDriver, and returns the corresponding clusterCSIDriver object, and an error if there is any.
func (c *FakeClusterCSIDrivers) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.ClusterCSIDriver, err error) {
	emptyResult := &v1.ClusterCSIDriver{}
	obj, err := c.Fake.
		Invokes(testing.NewRootGetActionWithOptions(clustercsidriversResource, name, options), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.ClusterCSIDriver), err
}

// List takes label and field selectors, and returns the list of ClusterCSIDrivers that match those selectors.
func (c *FakeClusterCSIDrivers) List(ctx context.Context, opts metav1.ListOptions) (result *v1.ClusterCSIDriverList, err error) {
	emptyResult := &v1.ClusterCSIDriverList{}
	obj, err := c.Fake.
		Invokes(testing.NewRootListActionWithOptions(clustercsidriversResource, clustercsidriversKind, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.ClusterCSIDriverList{ListMeta: obj.(*v1.ClusterCSIDriverList).ListMeta}
	for _, item := range obj.(*v1.ClusterCSIDriverList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested clusterCSIDrivers.
func (c *FakeClusterCSIDrivers) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchActionWithOptions(clustercsidriversResource, opts))
}

// Create takes the representation of a clusterCSIDriver and creates it.  Returns the server's representation of the clusterCSIDriver, and an error, if there is any.
func (c *FakeClusterCSIDrivers) Create(ctx context.Context, clusterCSIDriver *v1.ClusterCSIDriver, opts metav1.CreateOptions) (result *v1.ClusterCSIDriver, err error) {
	emptyResult := &v1.ClusterCSIDriver{}
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateActionWithOptions(clustercsidriversResource, clusterCSIDriver, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.ClusterCSIDriver), err
}

// Update takes the representation of a clusterCSIDriver and updates it. Returns the server's representation of the clusterCSIDriver, and an error, if there is any.
func (c *FakeClusterCSIDrivers) Update(ctx context.Context, clusterCSIDriver *v1.ClusterCSIDriver, opts metav1.UpdateOptions) (result *v1.ClusterCSIDriver, err error) {
	emptyResult := &v1.ClusterCSIDriver{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateActionWithOptions(clustercsidriversResource, clusterCSIDriver, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.ClusterCSIDriver), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeClusterCSIDrivers) UpdateStatus(ctx context.Context, clusterCSIDriver *v1.ClusterCSIDriver, opts metav1.UpdateOptions) (result *v1.ClusterCSIDriver, err error) {
	emptyResult := &v1.ClusterCSIDriver{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceActionWithOptions(clustercsidriversResource, "status", clusterCSIDriver, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.ClusterCSIDriver), err
}

// Delete takes name of the clusterCSIDriver and deletes it. Returns an error if one occurs.
func (c *FakeClusterCSIDrivers) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(clustercsidriversResource, name, opts), &v1.ClusterCSIDriver{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeClusterCSIDrivers) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewRootDeleteCollectionActionWithOptions(clustercsidriversResource, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1.ClusterCSIDriverList{})
	return err
}

// Patch applies the patch and returns the patched clusterCSIDriver.
func (c *FakeClusterCSIDrivers) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.ClusterCSIDriver, err error) {
	emptyResult := &v1.ClusterCSIDriver{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(clustercsidriversResource, name, pt, data, opts, subresources...), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.ClusterCSIDriver), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied clusterCSIDriver.
func (c *FakeClusterCSIDrivers) Apply(ctx context.Context, clusterCSIDriver *operatorv1.ClusterCSIDriverApplyConfiguration, opts metav1.ApplyOptions) (result *v1.ClusterCSIDriver, err error) {
	if clusterCSIDriver == nil {
		return nil, fmt.Errorf("clusterCSIDriver provided to Apply must not be nil")
	}
	data, err := json.Marshal(clusterCSIDriver)
	if err != nil {
		return nil, err
	}
	name := clusterCSIDriver.Name
	if name == nil {
		return nil, fmt.Errorf("clusterCSIDriver.Name must be provided to Apply")
	}
	emptyResult := &v1.ClusterCSIDriver{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(clustercsidriversResource, *name, types.ApplyPatchType, data, opts.ToPatchOptions()), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.ClusterCSIDriver), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeClusterCSIDrivers) ApplyStatus(ctx context.Context, clusterCSIDriver *operatorv1.ClusterCSIDriverApplyConfiguration, opts metav1.ApplyOptions) (result *v1.ClusterCSIDriver, err error) {
	if clusterCSIDriver == nil {
		return nil, fmt.Errorf("clusterCSIDriver provided to Apply must not be nil")
	}
	data, err := json.Marshal(clusterCSIDriver)
	if err != nil {
		return nil, err
	}
	name := clusterCSIDriver.Name
	if name == nil {
		return nil, fmt.Errorf("clusterCSIDriver.Name must be provided to Apply")
	}
	emptyResult := &v1.ClusterCSIDriver{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(clustercsidriversResource, *name, types.ApplyPatchType, data, opts.ToPatchOptions(), "status"), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.ClusterCSIDriver), err
}
