//go:build framework

package sdk

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-azurerm/internal/clients"
)

type TestProvider struct {
	Client *clients.Client
}

func (t TestProvider) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{}, nil
}

func (t TestProvider) Configure(_ context.Context, _ tfsdk.ConfigureProviderRequest, _ *tfsdk.ConfigureProviderResponse) {
}

func (t TestProvider) GetResources(_ context.Context) (map[string]tfsdk.ResourceType, diag.Diagnostics) {
	return map[string]tfsdk.ResourceType{
		"validator_decoder": testResourceType{},
	}, nil
}

func (t TestProvider) GetDataSources(_ context.Context) (map[string]tfsdk.DataSourceType, diag.Diagnostics) {
	return map[string]tfsdk.DataSourceType{}, nil
}

type testResourceType struct{}

func (t testResourceType) GetSchema(ctx context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"id": { // TODO - take this out and pipe through shim?
				Type:     types.StringType,
				Computed: true,
			},
			"hello": {
				Type:     types.StringType,
				Computed: true,
			},
			"random_number": {
				Type:     types.Int64Type,
				Computed: true,
			},
			"enabled": {
				Type:     types.BoolType,
				Computed: true,
			},
			"list_of_strings": {
				Type: types.ListType{
					ElemType: types.StringType,
				},
				Computed: true,
			},
			"list_of_numbers": {
				Type: types.ListType{
					ElemType: types.Int64Type,
				},
				Computed: true,
			},
			"list_of_bools": {
				Type: types.ListType{
					ElemType: types.BoolType,
				},
				Computed: true,
			},
			//"list_of_floats": {
			//	Type: types.ListType{
			//		ElemType: types.Float64Type,
			//	},
			//	Computed: true,
			//},
			"map_of_strings": {
				Type: types.MapType{
					ElemType: types.StringType,
				},
				Computed: true,
			},
			"map_of_numbers": {
				Type: types.MapType{
					ElemType: types.Int64Type,
				},
				Computed: true,
			},
			"map_of_bools": {
				Type: types.MapType{
					ElemType: types.BoolType,
				},
				Computed: true,
			},
			//"map_of_floats": {
			//	Type: types.MapType{
			//		ElemType: types.Float64Type,
			//	},
			//	Computed: true,
			//},
		},
		Blocks: map[string]tfsdk.Block{
			"nested_object": {
				Attributes: map[string]tfsdk.Attribute{
					"key": {
						Type:     types.StringType,
						Computed: true,
					},
				},
				NestingMode: tfsdk.BlockNestingMode(tfsdk.NestingModeList),
			},
		},
	}, nil
}

func (t testResourceType) NewResource(ctx context.Context, provider tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return testResource{}, nil
}

type testResource struct {
}

func (t testResource) Create(ctx context.Context, request tfsdk.CreateResourceRequest, response *tfsdk.CreateResourceResponse) {
	// TODO - This currently is not working - Floats get a big.Float conversion error, and the read fails to populate the state?
	// Possibly needs starting again at this point?
	response.State.SetAttribute(ctx, tftypes.NewAttributePath().WithAttributeName("id"), "some-id")
	response.State.SetAttribute(ctx, tftypes.NewAttributePath().WithAttributeName("hello"), "world")
	response.State.SetAttribute(ctx, tftypes.NewAttributePath().WithAttributeName("random_number"), 42)
	response.State.SetAttribute(ctx, tftypes.NewAttributePath().WithAttributeName("enabled"), true)
	response.State.SetAttribute(ctx, tftypes.NewAttributePath().WithAttributeName("list_of_strings"), []string{"hello", "there"})
	response.State.SetAttribute(ctx, tftypes.NewAttributePath().WithAttributeName("list_of_numbers"), []int{1, 2, 4})
	response.State.SetAttribute(ctx, tftypes.NewAttributePath().WithAttributeName("list_of_bools"), []bool{true, false})
	response.State.SetAttribute(ctx, tftypes.NewAttributePath().WithAttributeName("list_of_floats"), []float64{-1.234567894321, 2.3456789})
	response.State.SetAttribute(ctx, tftypes.NewAttributePath().WithAttributeName("map_of_strings"), map[string]string{
		"bingo": "bango",
	})
	response.State.SetAttribute(ctx, tftypes.NewAttributePath().WithAttributeName("map_of_numbers"), map[string]int{
		"lucky": 13,
	})
	response.State.SetAttribute(ctx, tftypes.NewAttributePath().WithAttributeName("map_of_bools"), map[string]bool{
		"friday": true,
	})
	response.State.SetAttribute(ctx, tftypes.NewAttributePath().WithAttributeName("map_of_floats"), map[string]float64{
		"pi": 3.14159,
	})
	response.State.SetAttribute(ctx, tftypes.NewAttributePath().WithAttributeName("nested_object"), []interface{}{
		map[string]interface{}{
			"key": "value",
		},
	})

	resourceData := NewFrameworkResourceData(ctx, &response.State)
	resourceData.WithConfig(request.Config)
	resourceData.WithPlan(request.Plan)
	readReq := tfsdk.ReadResourceRequest{
		State:        *resourceData.state,
		ProviderMeta: request.ProviderMeta,
	}

	readResp := &tfsdk.ReadResourceResponse{
		State:       response.State,
		Diagnostics: response.Diagnostics,
	}

	t.Read(ctx, readReq, readResp)
}

func (t testResource) Read(ctx context.Context, request tfsdk.ReadResourceRequest, response *tfsdk.ReadResourceResponse) {
	type NestedType struct {
		Key string `tfschema:"key"`
	}

	type MyType struct {
		Hello         string   `tfschema:"hello"`
		RandomNumber  int      `tfschema:"random_number"`
		Enabled       bool     `tfschema:"enabled"`
		ListOfStrings []string `tfschema:"list_of_strings"`
		ListOfNumbers []int    `tfschema:"list_of_numbers"`
		ListOfBools   []bool   `tfschema:"list_of_bools"`
		// ListOfFloats  []float64          `tfschema:"list_of_floats"`
		NestedObject []NestedType      `tfschema:"nested_object"`
		MapOfStrings map[string]string `tfschema:"map_of_strings"`
		MapOfNumbers map[string]int    `tfschema:"map_of_numbers"`
		MapOfBools   map[string]bool   `tfschema:"map_of_bools"`
		// MapOfFloats   map[string]float64 `tfschema:"map_of_floats"`
	}

	expected := MyType{
		Hello:         "world",
		RandomNumber:  42,
		Enabled:       true,
		ListOfStrings: []string{"hello", "there"},
		ListOfNumbers: []int{1, 2, 4},
		ListOfBools:   []bool{true, false},
		// ListOfFloats:  []float64{-1.234567894321, 2.3456789},
		NestedObject: []NestedType{
			{
				Key: "value",
			},
		},
		MapOfStrings: map[string]string{
			"bingo": "bango",
		},
		MapOfNumbers: map[string]int{
			"lucky": 13,
		},
		MapOfBools: map[string]bool{
			"friday": true,
		},
		//MapOfFloats: map[string]float64{
		//	"pi": 3.14159,
		//},
	}

	wrapper := ResourceMetaData{
		ResourceData:             NewFrameworkResourceData(ctx, &request.State),
		Logger:                   ConsoleLogger{},
		serializationDebugLogger: ConsoleLogger{},
	}

	var actual MyType

	if err := wrapper.Decode(&actual); err != nil {
		response.Diagnostics.AddError("decoding resource", err.Error())
	}

	if !reflect.DeepEqual(actual, expected) {
		response.Diagnostics.AddError("actual and expected not equal", fmt.Sprintf("expected %#v, got %#v", expected, actual))
	}

}

func (t testResource) Update(ctx context.Context, request tfsdk.UpdateResourceRequest, response *tfsdk.UpdateResourceResponse) {
	//TODO implement me?
}

func (t testResource) Delete(ctx context.Context, request tfsdk.DeleteResourceRequest, response *tfsdk.DeleteResourceResponse) {
	//TODO implement me?
}

func TestAccPluginFrameworkAndDecoder(t *testing.T) {
	os.Setenv("TF_ACC", "1")

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"validator": providerserver.NewProtocol6WithError(TestProvider{}),
		},
		Steps: []resource.TestStep{
			{
				Config: `resource "validator_decoder" "test" {}`,
			},
		},
	})
}
