//go:build framework
// +build framework

package provider

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-provider-azurerm/version"

	"github.com/hashicorp/terraform-plugin-framework/provider/schema"

	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/hashicorp/terraform-plugin-framework/datasource"

	"github.com/hashicorp/go-azure-helpers/authentication"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-azurerm/internal/clients"
	"github.com/hashicorp/terraform-provider-azurerm/internal/sdk"
)

var _ provider.Provider = &Provider{}

func AzureProvider() provider.Provider {
	return &Provider{}
}

type Provider struct {
	Client *clients.Client
}

func (p *Provider) Metadata(_ context.Context, _ provider.MetadataRequest, response *provider.MetadataResponse) {
	response.TypeName = "azurerm"
	response.Version = version.ProviderVersion
}

// Schema should return the schema for this provider.
func (p *Provider) Schema(ctx context.Context, request provider.SchemaRequest, response *provider.SchemaResponse) {
	response.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"subscription_id": schema.StringAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				Description: "The Subscription ID which should be used.",
			},

			"client_id": schema.StringAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				Description: "The Client ID which should be used.",
			},

			"tenant_id": schema.StringAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				Description: "The Tenant ID which should be used.",
			},
			"environment": schema.StringAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				Description: "The Cloud Environment which should be used. Possible values are public, usgovernment, and china. Defaults to public.",
			},

			"auxiliary_tenant_ids": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				//// TODO: can't do minimum items
				//MaxItems: 3,
				// perhaps this can be done via Validators but :shrug:
				//Validators: []tfsdk.AttributeValidator{
				//
				//},
			},

			"metadata_host": schema.StringAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				Description: "The Hostname which should be used for the Azure Metadata Service.",
			},

			// Client Certificate specific fields
			"client_certificate_path": schema.StringAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				Description: "The path to the Client Certificate associated with the Service Principal for use when authenticating as a Service Principal using a Client Certificate.",
			},

			"client_certificate_password": schema.StringAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				Description: "The password associated with the Client Certificate. For use when authenticating as a Service Principal using a Client Certificate",
			},

			// Client Secret specific fields
			"client_secret": schema.StringAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				Description: "The Client Secret which should be used. For use When authenticating as a Service Principal using a Client Secret.",
			},

			// Managed Service Identity specific fields
			"use_msi": schema.BoolAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				Description: "Allowed Managed Service Identity be used for Authentication.",
			},
			"msi_endpoint": schema.StringAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				Description: "The path to a custom endpoint for Managed Service Identity - in most circumstances this should be detected automatically. ",
			},

			// Managed Tracking GUID for User-agent
			"partner_id": schema.StringAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				// TODO: missing a helper to do UUID validation
				Description: "A GUID/UUID that is registered with Microsoft to facilitate partner resource usage attribution.",
			},

			"disable_correlation_request_id": schema.BoolAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				Description: "This will disable the x-ms-correlation-request-id header.",
			},

			"disable_terraform_partner_id": schema.BoolAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				Description: "This will disable the Terraform Partner ID which is used if a custom `partner_id` isn't specified.",
			},

			// TODO: Should `features` remain a block?
			"features": schemaFeaturesAttributes(),

			// Advanced feature flags
			"skip_provider_registration": schema.BoolAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				Description: "Should the AzureRM Provider skip registering all of the Resource Providers that it supports, if they're not already registered?",
			},

			"storage_use_azuread": schema.BoolAttribute{
				Optional: true,
				// TODO: missing the ability to specify a default value
				// TODO: missing the ability to source values from an environment variable
				Description: "Should the AzureRM Provider use AzureAD to access the Storage Data Plane API's?",
			},
		},
		// TODO: can we feature-toggle Blocks vs Attributes?
		DeprecationMessage:  "",
		Description:         "",
		MarkdownDescription: "",
	}
}

// Configure is called at the beginning of the provider lifecycle, when
// Terraform sends to the provider the values the user specified in the
// provider configuration block. These are supplied in the
// ConfigureProviderRequest argument.
// Values from provider configuration are often used to initialise an
// API client, which should be stored on the struct implementing the
// Provider interface.
func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	builder := &authentication.Builder{
		// TODO: parse the config
		SubscriptionID: os.Getenv("ARM_SUBSCRIPTION_ID"),
		ClientID:       os.Getenv("ARM_CLIENT_ID"),
		ClientSecret:   os.Getenv("ARM_CLIENT_SECRET"),
		TenantID:       os.Getenv("ARM_TENANT_ID"),
		Environment:    "public",
		MetadataHost:   "",

		// Feature Toggles
		SupportsClientSecretAuth: true,

		// Doc Links
		ClientSecretDocsLink: "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/guides/service_principal_client_secret",

		// Use MSAL
		UseMicrosoftGraph: true,
	}

	config, err := builder.Build()
	if err != nil {
		resp.Diagnostics.AddError("internal-error", fmt.Sprintf("building client: %+v", err))
		return
	}

	clientBuilder := clients.ClientBuilder{
		AuthConfig:               config,
		SkipProviderRegistration: false,
		TerraformVersion:         req.TerraformVersion,
		Features:                 expandFeatures([]interface{}{}),
	}

	client, err := clients.Build(ctx, clientBuilder)
	if err != nil {
		resp.Diagnostics.AddError("internal-error", fmt.Sprintf("building client: %+v", err))
		return
	}

	p.Client = client
}

// TODO: below here is boilerplate to workaround circular references in Framework

func (p *Provider) DataSources(ctx context.Context) []func() datasource.DataSource {
	dataSources := make([]func() datasource.DataSource, 0)

	for _, registration := range SupportedTypedServices() {
		for _, v := range registration.DataSources() {
			ds := sdk.NewDataSourceBuilder(v).NewDataSource()(ctx, p.Client)
			dataSources = append(dataSources, func() datasource.DataSource {
				data := ds
				return data
			})
		}
	}

	return dataSources
}

func (p *Provider) Resources(ctx context.Context) []func() resource.Resource {
	resources := make([]func() resource.Resource, 0)

	for _, registration := range SupportedTypedServices() {
		for _, v := range registration.Resources() {
			r := sdk.NewResourceBuilder(v).NewResource()(ctx, p.Client)
			resources = append(resources, func() resource.Resource {
				res := r
				return res
			})
		}
	}

	return resources
}

func schemaFeaturesAttributes() schema.Attribute {
	return schema.SingleNestedAttribute{
		// TODO: max 1
		Attributes: map[string]schema.Attribute{
			"resource_group": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"prevent_deletion_if_contains_resources": schema.BoolAttribute{
						Optional: true,
					},
				},
			},
		},
		Required:    true,
		Description: "The features map allows control of Azure features and behaviours within the provider.",
	}
}
