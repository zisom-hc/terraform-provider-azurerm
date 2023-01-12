//go:build framework
// +build framework

package sdk

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-provider-azurerm/internal/clients"
)

type ResourceBuilderWrapper interface {
	// NewResource instantiates a new Resource of this ResourceType.
	NewResource() func(context.Context, *clients.Client) resource.Resource
}

var _ ResourceBuilderWrapper = resourceBuilder{}

var _ resource.Resource = resourceWrapper{}

type resourceBuilder struct {
	typedResource Resource
}

func NewResourceBuilder(typedResource Resource) resourceBuilder {
	return resourceBuilder{
		typedResource: typedResource,
	}
}

func (r resourceBuilder) NewResource() func(context.Context, *clients.Client) resource.Resource {
	return func(ctx context.Context, client *clients.Client) resource.Resource {
		return resourceWrapper{
			typedResource: r.typedResource,
			client:        client,
		}
	}
}

type resourceWrapper struct {
	typedResource Resource
	client        *clients.Client
}

func (r resourceWrapper) Metadata(ctx context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	// TODO: ResourceType doesn't need to include the `azurerm` prefix since this comes from `request.ProviderTypeName`
	response.TypeName = r.typedResource.ResourceType()
}

func (r resourceWrapper) Schema(ctx context.Context, request resource.SchemaRequest, response *resource.SchemaResponse) {
	attributes := make(map[string]schema.Attribute, 0)

	for k, v := range r.typedResource.Attributes() {
		attr, err := frameworkResourceAttributeFromPluginSdkType(v)
		if err != nil {
			response.Diagnostics.AddError("internal-error", err.Error())
			return
		}

		attributes[k] = attr
	}
	for k, v := range r.typedResource.Arguments() {
		attr, err := frameworkResourceAttributeFromPluginSdkType(v)
		if err != nil {
			response.Diagnostics.AddError("internal-error", err.Error())
			return
		}

		attributes[k] = attr
	}

	// Add implicit 'id' attribute
	attributes["id"] = schema.StringAttribute{
		Computed: true,
	}

	version := 0
	if v, ok := r.typedResource.(ResourceWithStateMigration); ok {
		// TODO support state migrations
		version = v.StateUpgraders().SchemaVersion
	}

	response.Schema = schema.Schema{
		Attributes: attributes,
		Version:    int64(version),
	}
}

func (r resourceWrapper) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	f := r.typedResource.Create()

	resourceData := NewFrameworkResourceData(ctx, &response.State)
	resourceData.WithConfig(request.Config)
	resourceData.WithPlan(request.Plan)
	err := f.Func(ctx, ResourceMetaData{
		Client:                   r.client,
		Logger:                   NullLogger{},
		ResourceData:             resourceData,
		ResourceDiff:             nil,
		serializationDebugLogger: &DiagnosticsLogger{},
	})
	if err != nil {
		response.Diagnostics.AddError("performing create", err.Error())
		return
	}

	readReq := resource.ReadRequest{
		State:        *resourceData.state,
		ProviderMeta: request.ProviderMeta,
	}

	readResp := &resource.ReadResponse{
		State:       response.State,
		Diagnostics: response.Diagnostics,
	}

	r.Read(ctx, readReq, readResp)

	response.State = readResp.State
}

func (r resourceWrapper) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	f := r.typedResource.Read()

	resourceData := NewFrameworkResourceData(ctx, &response.State)
	resourceData.WithExistingState(request.State)
	err := f.Func(ctx, ResourceMetaData{
		Client:                   r.client,
		Logger:                   NullLogger{},
		ResourceData:             resourceData,
		ResourceDiff:             nil,
		serializationDebugLogger: &DiagnosticsLogger{},
	})
	if err != nil {
		response.Diagnostics.AddError("performing read", err.Error())
		return
	}

	response.State = *resourceData.state
}

func (r resourceWrapper) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	rwu, ok := r.typedResource.(ResourceWithUpdate)
	if !ok {
		response.Diagnostics.AddError("doesn't support update", "this resource does not support update")
		return
	}

	f := rwu.Update()

	resourceData := NewFrameworkResourceData(ctx, &response.State)
	resourceData.WithConfig(request.Config)
	resourceData.WithExistingState(request.State)
	resourceData.WithPlan(request.Plan)
	err := f.Func(ctx, ResourceMetaData{
		Client:                   r.client,
		Logger:                   NullLogger{},
		ResourceData:             resourceData,
		ResourceDiff:             nil,
		serializationDebugLogger: &DiagnosticsLogger{},
	})
	if err != nil {
		response.Diagnostics.AddError("performing update", err.Error())
		return
	}

	readReq := resource.ReadRequest{
		State:        *resourceData.state,
		ProviderMeta: request.ProviderMeta,
	}

	readResp := &resource.ReadResponse{
		State:       response.State,
		Diagnostics: response.Diagnostics,
	}

	r.Read(ctx, readReq, readResp)

	response.State = readResp.State
}

func (r resourceWrapper) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	f := r.typedResource.Delete()

	// TODO: note the request doesn't define the config for the schema here, but it should
	resourceData := NewFrameworkResourceData(ctx, &response.State)
	resourceData.WithExistingState(request.State)
	err := f.Func(ctx, ResourceMetaData{
		Client:                   r.client,
		Logger:                   NullLogger{},
		ResourceData:             resourceData,
		ResourceDiff:             nil,
		serializationDebugLogger: nil,
	})
	if err != nil {
		response.Diagnostics.AddError("performing delete", err.Error())
		return
	}

	response.State = *resourceData.state
}

func (r resourceWrapper) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	rwi, ok := r.typedResource.(ResourceWithCustomImporter)
	if ok {
		f := rwi.CustomImporter()
		resourceData := NewFrameworkResourceData(ctx, &response.State)
		resourceData.WithExistingID(request.ID)
		err := f(ctx, ResourceMetaData{
			Client:                   r.client,
			Logger:                   NullLogger{},
			ResourceData:             resourceData,
			ResourceDiff:             nil,
			serializationDebugLogger: &DiagnosticsLogger{},
		})
		if err != nil {
			response.Diagnostics.AddError("performing import", err.Error())
			return
		}

		response.State = *resourceData.state
	} else {
		f := r.typedResource.Read()
		resourceData := NewFrameworkResourceData(ctx, &response.State)
		resourceData.WithExistingID(request.ID)
		err := f.Func(ctx, ResourceMetaData{
			Client:                   r.client,
			Logger:                   NullLogger{},
			ResourceData:             resourceData,
			ResourceDiff:             nil,
			serializationDebugLogger: &DiagnosticsLogger{},
		})
		if err != nil {
			response.Diagnostics.AddError("performing import", err.Error())
			return
		}

		response.State = *resourceData.state
	}
}
