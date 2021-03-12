package mssql

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"

	"github.com/Azure/azure-sdk-for-go/services/preview/sql/mgmt/v3.0/sql"
	"github.com/Azure/go-autorest/autorest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/tf"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/clients"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/mssql/parse"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/mssql/validate"
	azSchema "github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/tf/schema"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/timeouts"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

func resourceMsSqlSyncGroup() *schema.Resource {
	return &schema.Resource{
		Create: resourceMsSqlSyncGroupCreateUpdate,
		Read:   resourceMsSqlSyncGroupRead,
		Update: resourceMsSqlSyncGroupCreateUpdate,
		Delete: resourceMsSqlSyncGroupDelete,

		Importer: azSchema.ValidateResourceIDPriorToImport(func(id string) error {
			_, err := parse.SyncGroupID(id)
			return err
		}),

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(20 * time.Minute),
			Read:   schema.DefaultTimeout(5 * time.Minute),
			Update: schema.DefaultTimeout(20 * time.Minute),
			Delete: schema.DefaultTimeout(20 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringIsNotEmpty, // TODO: validatefunc needed
			},

			"conflict_resolution_policy": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.StringInSlice([]string{
					string(sql.HubWin),
					string(sql.MemberWin),
				}, false),
			},

			"interval": {
				Type:     schema.TypeInt,
				Optional: true,
				// TODO What's a valid interval?
			},

			"hub_database_id": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validate.DatabaseID,
			},

			"hub_database_username": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringIsNotEmpty,
			},

			"hub_database_password": {
				Type:         schema.TypeString,
				Required:     true,
				Sensitive:    true,
				ValidateFunc: validation.StringIsNotEmpty,
			},

			"sync_database_id": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validate.DatabaseID,
			},

			"primary_sync_member_name": {
				Type:     schema.TypeString,
				Optional: true,
				// TODO validation
			},

			"table": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
							// TODO ValidateFunc for table name
						},

						"column": {
							Type:     schema.TypeList,
							Optional: true,
							MinItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Required: true,
										// TODO ValidateFunc for field name
									},

									"data_size": {
										Type:     schema.TypeString,
										Required: true,
									},

									"data_type": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func resourceMsSqlSyncGroupCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).MSSQL.SyncGroupsClient
	ctx, cancel := timeouts.ForCreateUpdate(meta.(*clients.Client).StopContext, d)
	defer cancel()

	name := d.Get("name").(string)
	hubUsername := d.Get("hub_database_username").(string)
	hubPassword := d.Get("hub_database_password").(string)
	syncDatabaseId := d.Get("sync_database_id").(string)

	hubId, err := parse.DatabaseID(d.Get("hub_database_id").(string))
	if err != nil {
		return err
	}

	id := parse.NewSyncGroupID(hubId.SubscriptionId, hubId.ResourceGroup, hubId.ServerName, hubId.Name, name)

	if d.IsNewResource() {
		existing, err := client.Get(ctx, id.ResourceGroup, id.ServerName, id.DatabaseName, id.Name)
		if err != nil {
			if !utils.ResponseWasNotFound(existing.Response) {
				return fmt.Errorf("checking for presence of existing MSSQL %s: %+v", id.String(), err)
			}
		}

		if existing.ID != nil && *existing.ID != "" {
			return tf.ImportAsExistsError("azurerm_mssql_sync_group", id.ID())
		}

		syncGroup := sql.SyncGroup{
			SyncGroupProperties: &sql.SyncGroupProperties{
				ConflictResolutionPolicy: sql.SyncConflictResolutionPolicy(d.Get("conflict_resolution_policy").(string)),
				HubDatabaseUserName:      utils.String(hubUsername),
				HubDatabasePassword:      utils.String(hubPassword),
				SyncDatabaseID:           utils.String(syncDatabaseId),
			},
		}

		future, err := client.CreateOrUpdate(ctx, id.ResourceGroup, id.ServerName, id.DatabaseName, id.Name, syncGroup)
		if err != nil {
			return fmt.Errorf("creating/updating MSSQL %s: %+v", id.String(), err)
		}
		if err = future.WaitForCompletionRef(ctx, client.Client); err != nil {
			if derr, ok := err.(autorest.DetailedError); ok && derr.Original != nil {
				return fmt.Errorf("creating/updating MSSQL %s: %+v", id.String(), derr.Original)
			}
			return fmt.Errorf("waiting on create/update operation for MSSQL %s: %+v", id.String(), err)
		}
	}

	d.SetId(id.ID())

	log.Printf("[DEBUG] Refreshing hub schema for %s", id.String())
	refreshFuture, err := client.RefreshHubSchema(ctx, id.ResourceGroup, id.ServerName, id.DatabaseName, id.Name)
	if err != nil {
		return fmt.Errorf("refreshing schema for MSSQL %s: %+v", id.String(), err)
	}
	if err = refreshFuture.WaitForCompletionRef(ctx, client.Client); err != nil {
		return fmt.Errorf("waiting on schema refresh operation for MSSQL %s: %+v", id.String(), err)
	}

	log.Printf("[DEBUG] Waiting for hub schema to refresh for MSSQL %s", id.String())
	timeout, _ := ctx.Deadline()
	stateConf := &resource.StateChangeConf{
		Pending:    []string{"pending"},
		Target:     []string{"found"},
		Refresh:    mssqlSyncGroupHubSchemaRefreshFunc(ctx, client, id),
		MinTimeout: 10 * time.Second,
		Timeout:    time.Until(timeout),
	}

	if _, err := stateConf.WaitForState(); err != nil {
		return fmt.Errorf("waiting for hub schema to refresh for MSSQL %s: %+v", id.String(), err)
	}

	tables := d.Get("table")

	syncGroupUpdate := sql.SyncGroup{
		SyncGroupProperties: &sql.SyncGroupProperties{
			Schema: &sql.SyncGroupSchema{
				MasterSyncMemberName: utils.String(id.DatabaseName),
				Tables:               expandMsSqlSyncGroupSchemaTables(tables.([]interface{})),
			},
		},
	}

	if interval, exists := d.GetOk("interval"); exists {
		syncGroupUpdate.SyncGroupProperties.Interval = utils.Int32(int32(interval.(int)))
	}

	//if primarySyncMemberName, exists := d.GetOk("primary_sync_member_name"); exists {
	//	syncGroupUpdate.SyncGroupProperties.Schema.MasterSyncMemberName = utils.String(primarySyncMemberName.(string))
	//}

	future, err := client.CreateOrUpdate(ctx, id.ResourceGroup, id.ServerName, id.DatabaseName, id.Name, syncGroupUpdate)
	if err != nil {
		return fmt.Errorf("creating/updating schema configuration for MSSQL %s: %+v", id.String(), err)
	}
	if err = future.WaitForCompletionRef(ctx, client.Client); err != nil {
		if derr, ok := err.(autorest.DetailedError); ok && derr.Original != nil {
			return fmt.Errorf("waiting on schema create/update operation for MSSQL %s: %+v", id.String(), derr.Original)
		}
		return fmt.Errorf("waiting on schema create/update operation for MSSQL %s: %+v", id.String(), err)
	}

	return resourceMsSqlSyncGroupRead(d, meta)
}

func resourceMsSqlSyncGroupRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).MSSQL.SyncGroupsClient
	ctx, cancel := timeouts.ForCreateUpdate(meta.(*clients.Client).StopContext, d)
	defer cancel()

	id, err := parse.SyncGroupID(d.Id())
	if err != nil {
		return err
	}

	resp, err := client.Get(ctx, id.ResourceGroup, id.ServerName, id.DatabaseName, id.Name)
	if err != nil {
		if utils.ResponseWasNotFound(resp.Response) {
			log.Printf("[INFO] Error reading MSSQL Sync Group %s - removing from state", d.Id())
			d.SetId("")
			return nil
		}

		return fmt.Errorf("reading MSSQL %s: %+v", id.String(), err)
	}

	databaseId := parse.NewDatabaseID(id.SubscriptionId, id.ResourceGroup, id.ServerName, id.DatabaseName)
	if err = d.Set("hub_database_id", databaseId.ID()); err != nil {
		return fmt.Errorf("setting %q", "hub_database_id")
	}

	if err = d.Set("name", resp.Name); err != nil {
		return fmt.Errorf("setting %q", "name")
	}

	if err = d.Set("conflict_resolution_policy", resp.ConflictResolutionPolicy); err != nil {
		return fmt.Errorf("setting %q", "conflict_resolution_policy")
	}

	if resp.Interval == nil {
		return fmt.Errorf("interval returned was null for MSSQL %s", id.String())
	} else if err = d.Set("interval", int(*resp.Interval)); err != nil {
		return fmt.Errorf("setting %q", "interval")
	}

	if err = d.Set("sync_database_id", resp.SyncDatabaseID); err != nil {
		return fmt.Errorf("setting %q", "sync_database_id")
	}

	if err = d.Set("hub_database_username", resp.HubDatabaseUserName); err != nil {
		return fmt.Errorf("setting %q", "hub_database_username")
	}

	if err = d.Set("hub_database_password", resp.HubDatabasePassword); err != nil {
		return fmt.Errorf("setting %q", "hub_database_password")
	}

	if resp.Schema != nil {
		if err = d.Set("primary_sync_member_name", resp.Schema.MasterSyncMemberName); err != nil {
			return fmt.Errorf("setting %q", "primary_sync_member_name")
		}

		if err = d.Set("table", flattenMsSqlSyncGroupSchemaTables(resp.Schema.Tables)); err != nil {
			return fmt.Errorf("setting %q", "table")
		}
	}

	return nil
}

func resourceMsSqlSyncGroupDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).MSSQL.SyncGroupsClient
	ctx, cancel := timeouts.ForDelete(meta.(*clients.Client).StopContext, d)
	defer cancel()

	id, err := parse.SyncGroupID(d.Id())
	if err != nil {
		return err
	}

	future, err := client.Delete(ctx, id.ResourceGroup, id.ServerName, id.DatabaseName, id.Name)
	if err != nil {
		return fmt.Errorf("deleting MSSQL %s: %+v", id.String(), err)
	}

	return future.WaitForCompletionRef(ctx, client.Client)
}

func mssqlSyncGroupHubSchemaRefreshFunc(ctx context.Context, client *sql.SyncGroupsClient, id parse.SyncGroupId) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		log.Printf("[DEBUG] Waiting for hub schemas to populate...")
		resp, err := client.ListHubSchemas(ctx, id.ResourceGroup, id.ServerName, id.DatabaseName, id.Name)
		if err != nil {
			return nil, "error", err
		}
		schemas := resp.Values()
		for _, schema := range schemas {
			if tables := schema.Tables; tables != nil {
				return schemas, "found", nil
			}
		}
		return schemas, "pending", nil
	}
}

func flattenMsSqlSyncGroupSchemaTables(tables *[]sql.SyncGroupSchemaTable) []interface{} {
	if tables == nil {
		return []interface{}{}
	}

	out := make([]interface{}, 0, len(*tables))

	for _, table := range *tables {
		name := ""
		if table.QuotedName != nil {
			name = *table.QuotedName
		}

		out = append(out, map[string]interface{}{
			"name":   name,
			"column": flattenMsSqlSyncGroupSchemaTableColumns(table.Columns),
		})
	}
	return out
}

func flattenMsSqlSyncGroupSchemaTableColumns(columns *[]sql.SyncGroupSchemaTableColumn) []interface{} {
	if columns == nil {
		return []interface{}{}
	}

	out := make([]interface{}, 0, len(*columns))

	for _, column := range *columns {
		name := ""
		if column.QuotedName != nil {
			name = *column.QuotedName
		}

		dataSize := ""
		if column.DataSize != nil {
			dataSize = *column.DataSize
		}

		dataType := ""
		if column.DataType != nil {
			dataType = *column.DataType
		}

		out = append(out, map[string]interface{}{
			"name":      name,
			"data_size": dataSize,
			"data_type": dataType,
		})
	}

	return out
}

func expandMsSqlSyncGroupSchemaTables(tables []interface{}) *[]sql.SyncGroupSchemaTable {
	out := make([]sql.SyncGroupSchemaTable, 0, len(tables))

	for _, tableRaw := range tables {
		table := tableRaw.(map[string]interface{})
		outTable := sql.SyncGroupSchemaTable{
			Columns:    expandMsSqlSyncGroupSchemaTableColumns(table["column"].([]interface{})),
			QuotedName: utils.String(table["name"].(string)),
		}
		out = append(out, outTable)
	}
	return &out
}

func expandMsSqlSyncGroupSchemaTableColumns(columns []interface{}) *[]sql.SyncGroupSchemaTableColumn {
	out := make([]sql.SyncGroupSchemaTableColumn, 0, len(columns))

	for _, columnRaw := range columns {
		column := columnRaw.(map[string]interface{})
		outColumn := sql.SyncGroupSchemaTableColumn{
			QuotedName: utils.String(column["name"].(string)),
			DataSize:   utils.String(column["data_size"].(string)),
			DataType:   utils.String(column["data_type"].(string)),
		}
		out = append(out, outColumn)
	}
	return &out
}
