//go:build framework
// +build framework

package sdk

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-provider-azurerm/internal/clients"
)

type DataSourceBuilderWrapper interface {
	// NewDataSource instantiates a new DataSource of this DataSourceType.
	NewDataSource() func(context.Context, *clients.Client) datasource.DataSource
}

var _ DataSourceBuilderWrapper = dataSourceBuilder{}

type dataSourceBuilder struct {
	typedDataSource DataSource
}

func NewDataSourceBuilder(typedDataSource DataSource) dataSourceBuilder {
	return dataSourceBuilder{
		typedDataSource: typedDataSource,
	}
}

func (d dataSourceBuilder) NewDataSource() func(context.Context, *clients.Client) datasource.DataSource {
	return func(ctx context.Context, client *clients.Client) datasource.DataSource {
		return dataSourceWrapper{
			client:          client,
			typedDataSource: d.typedDataSource,
		}
	}
}

var _ datasource.DataSource = dataSourceWrapper{}

type dataSourceWrapper struct {
	client          *clients.Client
	typedDataSource DataSource
}

func (d dataSourceWrapper) Metadata(ctx context.Context, request datasource.MetadataRequest, response *datasource.MetadataResponse) {
	// TODO: the Resource Type doesn't need to include the prefix since this comes from `request.ProviderTypeName`
	response.TypeName = d.typedDataSource.ResourceType()
}

func (d dataSourceWrapper) Schema(ctx context.Context, request datasource.SchemaRequest, response *datasource.SchemaResponse) {
	attributes := make(map[string]schema.Attribute, 0)

	for k, v := range d.typedDataSource.Attributes() {
		attr, err := frameworkResourceAttributeFromPluginSdkType(v)
		if err != nil {
			response.Diagnostics.AddError("internal-error", err.Error())
			return
		}

		attributes[k] = attr
	}
	for k, v := range d.typedDataSource.Arguments() {
		attr, err := frameworkResourceAttributeFromPluginSdkType(v)
		if err != nil {
			response.Diagnostics.AddError("internal-error", err.Error())
			return
		}

		attributes[k] = attr
	}

	response.Schema = schema.Schema{
		Attributes: attributes,
	}
}

func (d dataSourceWrapper) Read(ctx context.Context, request datasource.ReadRequest, response *datasource.ReadResponse) {
	f := d.typedDataSource.Read()

	resourceData := NewFrameworkResourceData(ctx, &response.State)
	resourceData.WithConfig(request.Config)
	err := f.Func(ctx, ResourceMetaData{
		Client:                   d.client,
		Logger:                   NullLogger{},
		ResourceData:             resourceData,
		ResourceDiff:             nil,
		serializationDebugLogger: nil,
	})
	if err != nil {
		response.Diagnostics.AddError("performing read", err.Error())
		return
	}

	response.State = *resourceData.state
}
