package tombuildsstuff

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-azurerm/internal/sdk"
)

var _ sdk.DataSource = FakeDataSource{}

type FakeDataSource struct {
}

func (f FakeDataSource) Arguments() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"name": {
			Type:     schema.TypeString,
			Required: true,
		},
	}
}

func (f FakeDataSource) Attributes() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"location": {
			Type:     schema.TypeString,
			Computed: true,
		},
		// TODO: not yet supported in the shim
		"nested": {
			Type:     schema.TypeList,
			Computed: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"value": {
						Type:     schema.TypeString,
						Computed: true,
					},
				},
			},
		},
	}
}

func (f FakeDataSource) ModelObject() interface{} {
	return nil
}

func (f FakeDataSource) ResourceType() string {
	return "azurerm_fake"
}

func (f FakeDataSource) Read() sdk.ResourceFunc {
	return sdk.ResourceFunc{
		Func: func(ctx context.Context, metadata sdk.ResourceMetaData) error {
			metadata.ResourceData.SetId("tombuildsstuff")
			metadata.ResourceData.Set("location", "Berlin")
			// TODO: not yet supported in the shim
			// │ setting `nested`: setting attribute "Value Conversion Error: An unexpected error was encountered trying to convert from value. This is always an error in the provider. Please report the following to the provider developer:\n\ncannot
			//│ use type map[string]interface {} as schema type basetypes.ObjectType; basetypes.ObjectType must be an attr.TypeWithElementType to hold map[string]interface {}":
			err := metadata.ResourceData.Set("nested", []interface{}{
				map[string]interface{}{
					"value": "bob",
				},
			})
			if err != nil {
				return fmt.Errorf("setting `nested`: %+v", err)
			}
			return nil
		},
		Timeout: 10 * time.Minute,
	}
}
