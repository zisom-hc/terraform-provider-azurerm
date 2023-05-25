package client

import (
	"fmt"

	"github.com/hashicorp/go-azure-sdk/resource-manager/datafactory/2018-06-01/dataflowdebugsession"
	"github.com/hashicorp/go-azure-sdk/resource-manager/datafactory/2018-06-01/dataflows"
	"github.com/hashicorp/go-azure-sdk/resource-manager/datafactory/2018-06-01/datasets"
	"github.com/hashicorp/go-azure-sdk/resource-manager/datafactory/2018-06-01/factories"
	"github.com/hashicorp/go-azure-sdk/resource-manager/datafactory/2018-06-01/integrationruntimes"
	"github.com/hashicorp/go-azure-sdk/resource-manager/datafactory/2018-06-01/linkedservices"
	"github.com/hashicorp/go-azure-sdk/resource-manager/datafactory/2018-06-01/managedprivateendpoints"
	"github.com/hashicorp/go-azure-sdk/resource-manager/datafactory/2018-06-01/managedvirtualnetworks"
	"github.com/hashicorp/go-azure-sdk/resource-manager/datafactory/2018-06-01/pipelines"
	"github.com/hashicorp/go-azure-sdk/resource-manager/datafactory/2018-06-01/triggers"
	"github.com/hashicorp/terraform-provider-azurerm/internal/common"
)

type Client struct {
	DataFlowClient                *dataflows.DataFlowsClient
	DataFlowDebugSessionClient    *dataflowdebugsession.DataFlowDebugSessionClient
	DatasetClient                 *datasets.DatasetsClient
	FactoriesClient               *factories.FactoriesClient
	IntegrationRuntimesClient     *integrationruntimes.IntegrationRuntimesClient
	LinkedServiceClient           *linkedservices.LinkedServicesClient
	ManagedPrivateEndpointsClient *managedprivateendpoints.ManagedPrivateEndpointsClient
	ManagedVirtualNetworksClient  *managedvirtualnetworks.ManagedVirtualNetworksClient
	PipelinesClient               *pipelines.PipelinesClient
	TriggersClient                *triggers.TriggersClient
}

func NewClient(o *common.ClientOptions) (*Client, error) {
	dataFlowClient, err := dataflows.NewDataFlowsClientWithBaseURI(o.Environment.ResourceManager)
	if err != nil {
		return nil, fmt.Errorf("building DataFlowClient client: %+v", err)
	}
	o.Configure(dataFlowClient.Client, o.Authorizers.ResourceManager)

	dataFlowDebugSessionClient, err := dataflowdebugsession.NewDataFlowDebugSessionClientWithBaseURI(o.Environment.ResourceManager)
	if err != nil {
		return nil, fmt.Errorf("building DataFlowDebugSession client: %+v", err)
	}
	o.Configure(dataFlowDebugSessionClient.Client, o.Authorizers.ResourceManager)

	datasetClient, err := datasets.NewDatasetsClientWithBaseURI(o.Environment.ResourceManager)
	if err != nil {
		return nil, fmt.Errorf("building DatasetClient client: %+v", err)
	}
	o.Configure(datasetClient.Client, o.Authorizers.ResourceManager)

	factoriesClient, err := factories.NewFactoriesClientWithBaseURI(o.Environment.ResourceManager)
	if err != nil {
		return nil, fmt.Errorf("building FactoriesClient client: %+v", err)
	}
	o.Configure(factoriesClient.Client, o.Authorizers.ResourceManager)

	integrationRuntimesClient, err := integrationruntimes.NewIntegrationRuntimesClientWithBaseURI(o.Environment.ResourceManager)
	if err != nil {
		return nil, fmt.Errorf("building IntegrationRuntimesClient client: %+v", err)
	}
	o.Configure(integrationRuntimesClient.Client, o.Authorizers.ResourceManager)

	linkedServiceClient, err := linkedservices.NewLinkedServicesClientWithBaseURI(o.Environment.ResourceManager)
	if err != nil {
		return nil, fmt.Errorf("building LinkedServiceClient client: %+v", err)
	}
	o.Configure(linkedServiceClient.Client, o.Authorizers.ResourceManager)

	managedPrivateEndpointsClient, err := managedprivateendpoints.NewManagedPrivateEndpointsClientWithBaseURI(o.Environment.ResourceManager)
	if err != nil {
		return nil, fmt.Errorf("building ManagedPrivateEndpointsClient client: %+v", err)
	}
	o.Configure(managedPrivateEndpointsClient.Client, o.Authorizers.ResourceManager)

	managedVirtualNetworksClient, err := managedvirtualnetworks.NewManagedVirtualNetworksClientWithBaseURI(o.Environment.ResourceManager)
	if err != nil {
		return nil, fmt.Errorf("building ManagedVirtualNetworksClient client: %+v", err)
	}
	o.Configure(managedVirtualNetworksClient.Client, o.Authorizers.ResourceManager)

	pipelinesClient, err := pipelines.NewPipelinesClientWithBaseURI(o.Environment.ResourceManager)
	if err != nil {
		return nil, fmt.Errorf("building PipelinesClient client: %+v", err)
	}
	o.Configure(pipelinesClient.Client, o.Authorizers.ResourceManager)

	triggersClient, err := triggers.NewTriggersClientWithBaseURI(o.Environment.ResourceManager)
	if err != nil {
		return nil, fmt.Errorf("building TriggersClient client: %+v", err)
	}
	o.Configure(triggersClient.Client, o.Authorizers.ResourceManager)

	return &Client{
		DataFlowClient:                dataFlowClient,
		DataFlowDebugSessionClient:    dataFlowDebugSessionClient,
		DatasetClient:                 datasetClient,
		FactoriesClient:               factoriesClient,
		IntegrationRuntimesClient:     integrationRuntimesClient,
		LinkedServiceClient:           linkedServiceClient,
		ManagedPrivateEndpointsClient: managedPrivateEndpointsClient,
		ManagedVirtualNetworksClient:  managedVirtualNetworksClient,
		PipelinesClient:               pipelinesClient,
		TriggersClient:                triggersClient,
	}, nil
}
