package mssql_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/acceptance/check"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/mssql/parse"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/acceptance"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/clients"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

type MsSqlSyncGroupResource struct{}

func TestAccMsSqlSyncGroup_complete(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_mssql_sync_group", "test")
	r := MsSqlSyncGroupResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.complete(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccMsSqlSyncGroup_requiresImport(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_mssql_sync_group", "test")
	r := MsSqlSyncGroupResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.complete(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		{
			Config:      r.requiresImport(data),
			ExpectError: acceptance.RequiresImportError(data.ResourceType),
		},
	})
}

func (MsSqlSyncGroupResource) Exists(ctx context.Context, client *clients.Client, state *terraform.InstanceState) (*bool, error) {
	id, err := parse.SyncGroupID(state.ID)
	if err != nil {
		return nil, err
	}

	resp, err := client.MSSQL.SyncGroupsClient.Get(ctx, id.ResourceGroup, id.ServerName, id.DatabaseName, id.Name)
	if err != nil {
		if utils.ResponseWasNotFound(resp.Response) {
			return nil, fmt.Errorf("SQL Sync Group %q (database %q / server %q / resource group %q) does not exist", id.Name, id.DatabaseName, id.ServerName, id.ResourceGroup)
		}

		return nil, err
	}

	return utils.Bool(resp.ID != nil), nil
}

func (MsSqlSyncGroupResource) template(data acceptance.TestData) string {
	return fmt.Sprintf(`
%[1]s

resource "azurerm_mssql_"

resource "azurerm_mssql_database" "hub" {
  name        = "syncHub%[2]d"
  server_id   = azurerm_mssql_server.test.id
  sku_name    = "S2"
  sample_name = "AdventureWorksLT"
}

resource "azurerm_mssql_database" "sync" {
  name      = "syncStore%[2]d"
  server_id = azurerm_mssql_server.test.id
  sku_name  = "S1"
}
`, MsSqlServerResource{}.basic(data), data.RandomInteger)
}

func (r MsSqlSyncGroupResource) complete(data acceptance.TestData) string {
	return fmt.Sprintf(`
%s

resource "azurerm_mssql_sync_group" "test" {
  name = "acctest-syncgroup-%[2]d"

  hub_database_id       = azurerm_mssql_database.hub.id
  hub_database_username = azurerm_mssql_server.test.administrator_login
  hub_database_password = "thisIsKat11"

  conflict_resolution_policy = "HubWin"
  sync_database_id           = azurerm_mssql_database.sync.id
  //primary_sync_member_name   = azurerm_mssql_database.hub.name
  //interval = WUT

  table {
    name = "[SalesLT].[Product]"

    column {
      name      = "[ProductID]"
      data_size = "4"
      data_type = "int"
    }

    column {
      name      = "[ProductNumber]"
      data_size = "25"
      data_type = "nvarchar"
    }

    column {
      name      = "[Color]"
      data_size = "15"
      data_type = "nvarchar"
    }
  }
}
`, r.template(data), data.RandomInteger)
}

func (r MsSqlSyncGroupResource) requiresImport(data acceptance.TestData) string {
	return fmt.Sprintf(`
%s

resource "azurerm_mssql_sync_group" "import" {
  name                       = azurerm_mssql_sync_group.test.name
  resource_group_name        = azurerm_mssql_sync_group.test.resource_group_name
  server_name                = azurerm_mssql_sync_group.test.server_name
  database_name              = azurerm_mssql_sync_group.test.database_name
  conflict_resolution_policy = azurerm_mssql_sync_group.test.conflict_resolution_policy
  interval                   = azurerm_mssql_sync_group.test.interval
  sync_database_id           = azurerm_mssql_sync_group.test.sync_database_id
  hub_database_username      = azurerm_mssql_sync_group.test.hub_database_username
  hub_database_password      = azurerm_mssql_sync_group.test.hub_database_password
  primary_sync_member_name   = azurerm_mssql_sync_group.test.primary_sync_member_name
}
`, r.complete(data))
}
