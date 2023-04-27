package client

import (
	"github.com/hashicorp/go-azure-sdk/resource-manager/hdinsight/2018-06-01-preview/applications"
	"github.com/hashicorp/go-azure-sdk/resource-manager/hdinsight/2018-06-01-preview/clusters"
	"github.com/hashicorp/go-azure-sdk/resource-manager/hdinsight/2018-06-01-preview/configurations"
	"github.com/hashicorp/go-azure-sdk/resource-manager/hdinsight/2018-06-01-preview/extensions"
	"github.com/hashicorp/terraform-provider-azurerm/internal/common"
)

type Client struct {
	ApplicationsClient   *applications.ApplicationsClient
	ClustersClient       *clusters.ClustersClient
	ConfigurationsClient *configurations.ConfigurationsClient
	ExtensionsClient     *extensions.ExtensionsClient
}

func NewClient(o *common.ClientOptions) (*Client, error) {
	// due to a bug in the HDInsight API we can't reuse client with the same x-ms-correlation-request-id for multiple updates
	opts := *o
	opts.DisableCorrelationRequestID = true

	applicationsClient, err := applications.NewApplicationsClientWithBaseURI(opts.Environment.ResourceManager)
	if err != nil {
		return nil, err
	}
	opts.Configure(applicationsClient.Client, opts.Authorizers.ResourceManager)

	clustersClient, err := clusters.NewClustersClientWithBaseURI(opts.Environment.ResourceManager)
	if err != nil {
		return nil, err
	}
	opts.Configure(clustersClient.Client, opts.Authorizers.ResourceManager)

	configurationsClient, err := configurations.NewConfigurationsClientWithBaseURI(opts.Environment.ResourceManager)
	if err != nil {
		return nil, err
	}
	opts.Configure(configurationsClient.Client, opts.Authorizers.ResourceManager)

	extensionsClient, err := extensions.NewExtensionsClientWithBaseURI(opts.Environment.ResourceManager)
	if err != nil {
		return nil, err
	}
	opts.Configure(extensionsClient.Client, opts.Authorizers.ResourceManager)

	return &Client{
		ApplicationsClient:   applicationsClient,
		ClustersClient:       clustersClient,
		ConfigurationsClient: configurationsClient,
		ExtensionsClient:     extensionsClient,
	}, nil
}
