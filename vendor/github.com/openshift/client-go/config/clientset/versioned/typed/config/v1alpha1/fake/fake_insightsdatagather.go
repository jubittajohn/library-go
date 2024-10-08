// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	v1alpha1 "github.com/openshift/api/config/v1alpha1"
	configv1alpha1 "github.com/openshift/client-go/config/applyconfigurations/config/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeInsightsDataGathers implements InsightsDataGatherInterface
type FakeInsightsDataGathers struct {
	Fake *FakeConfigV1alpha1
}

var insightsdatagathersResource = v1alpha1.SchemeGroupVersion.WithResource("insightsdatagathers")

var insightsdatagathersKind = v1alpha1.SchemeGroupVersion.WithKind("InsightsDataGather")

// Get takes name of the insightsDataGather, and returns the corresponding insightsDataGather object, and an error if there is any.
func (c *FakeInsightsDataGathers) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.InsightsDataGather, err error) {
	emptyResult := &v1alpha1.InsightsDataGather{}
	obj, err := c.Fake.
		Invokes(testing.NewRootGetActionWithOptions(insightsdatagathersResource, name, options), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.InsightsDataGather), err
}

// List takes label and field selectors, and returns the list of InsightsDataGathers that match those selectors.
func (c *FakeInsightsDataGathers) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.InsightsDataGatherList, err error) {
	emptyResult := &v1alpha1.InsightsDataGatherList{}
	obj, err := c.Fake.
		Invokes(testing.NewRootListActionWithOptions(insightsdatagathersResource, insightsdatagathersKind, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.InsightsDataGatherList{ListMeta: obj.(*v1alpha1.InsightsDataGatherList).ListMeta}
	for _, item := range obj.(*v1alpha1.InsightsDataGatherList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested insightsDataGathers.
func (c *FakeInsightsDataGathers) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchActionWithOptions(insightsdatagathersResource, opts))
}

// Create takes the representation of a insightsDataGather and creates it.  Returns the server's representation of the insightsDataGather, and an error, if there is any.
func (c *FakeInsightsDataGathers) Create(ctx context.Context, insightsDataGather *v1alpha1.InsightsDataGather, opts v1.CreateOptions) (result *v1alpha1.InsightsDataGather, err error) {
	emptyResult := &v1alpha1.InsightsDataGather{}
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateActionWithOptions(insightsdatagathersResource, insightsDataGather, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.InsightsDataGather), err
}

// Update takes the representation of a insightsDataGather and updates it. Returns the server's representation of the insightsDataGather, and an error, if there is any.
func (c *FakeInsightsDataGathers) Update(ctx context.Context, insightsDataGather *v1alpha1.InsightsDataGather, opts v1.UpdateOptions) (result *v1alpha1.InsightsDataGather, err error) {
	emptyResult := &v1alpha1.InsightsDataGather{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateActionWithOptions(insightsdatagathersResource, insightsDataGather, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.InsightsDataGather), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeInsightsDataGathers) UpdateStatus(ctx context.Context, insightsDataGather *v1alpha1.InsightsDataGather, opts v1.UpdateOptions) (result *v1alpha1.InsightsDataGather, err error) {
	emptyResult := &v1alpha1.InsightsDataGather{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceActionWithOptions(insightsdatagathersResource, "status", insightsDataGather, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.InsightsDataGather), err
}

// Delete takes name of the insightsDataGather and deletes it. Returns an error if one occurs.
func (c *FakeInsightsDataGathers) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(insightsdatagathersResource, name, opts), &v1alpha1.InsightsDataGather{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeInsightsDataGathers) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionActionWithOptions(insightsdatagathersResource, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.InsightsDataGatherList{})
	return err
}

// Patch applies the patch and returns the patched insightsDataGather.
func (c *FakeInsightsDataGathers) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.InsightsDataGather, err error) {
	emptyResult := &v1alpha1.InsightsDataGather{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(insightsdatagathersResource, name, pt, data, opts, subresources...), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.InsightsDataGather), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied insightsDataGather.
func (c *FakeInsightsDataGathers) Apply(ctx context.Context, insightsDataGather *configv1alpha1.InsightsDataGatherApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.InsightsDataGather, err error) {
	if insightsDataGather == nil {
		return nil, fmt.Errorf("insightsDataGather provided to Apply must not be nil")
	}
	data, err := json.Marshal(insightsDataGather)
	if err != nil {
		return nil, err
	}
	name := insightsDataGather.Name
	if name == nil {
		return nil, fmt.Errorf("insightsDataGather.Name must be provided to Apply")
	}
	emptyResult := &v1alpha1.InsightsDataGather{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(insightsdatagathersResource, *name, types.ApplyPatchType, data, opts.ToPatchOptions()), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.InsightsDataGather), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeInsightsDataGathers) ApplyStatus(ctx context.Context, insightsDataGather *configv1alpha1.InsightsDataGatherApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.InsightsDataGather, err error) {
	if insightsDataGather == nil {
		return nil, fmt.Errorf("insightsDataGather provided to Apply must not be nil")
	}
	data, err := json.Marshal(insightsDataGather)
	if err != nil {
		return nil, err
	}
	name := insightsDataGather.Name
	if name == nil {
		return nil, fmt.Errorf("insightsDataGather.Name must be provided to Apply")
	}
	emptyResult := &v1alpha1.InsightsDataGather{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(insightsdatagathersResource, *name, types.ApplyPatchType, data, opts.ToPatchOptions(), "status"), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.InsightsDataGather), err
}
