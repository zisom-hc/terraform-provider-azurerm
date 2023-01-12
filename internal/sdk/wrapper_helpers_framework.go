//go:build framework
// +build framework

package sdk

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	resourceSchema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-azurerm/internal/tf/pluginsdk"
)

func frameworkResourceAttributeFromPluginSdkType(input *schema.Schema) (resourceSchema.Attribute, error) {
	if input.Type == schema.TypeBool {
		return booleanAttributeFromPluginSDKv2Resource(input), nil
	}
	if input.Type == schema.TypeFloat {
		return float64AttributeFromPluginSDKv2Resource(input), nil
	}
	if input.Type == schema.TypeInt {
		return int64AttributeFromPluginSDKv2Resource(input), nil
	}
	if input.Type == schema.TypeString {
		return stringAttributeFromPluginSDKv2Resource(input), nil
	}

	if input.Type == schema.TypeMap {
		if input.Elem == nil {
			return nil, fmt.Errorf("the Elem was nil for the Map type")
		}
		v, ok := input.Elem.(*schema.Schema)
		if !ok {
			return nil, fmt.Errorf("expected an Elem for the Map item")
		}

		nested, err := frameworkResourceAttributeFromPluginSdkType(v)
		if err != nil {
			return nil, fmt.Errorf("TODO: %+v", err)
		}

		return mapAttributeFromPluginSDKv2Resource(input, nested), nil
	}

	if input.Type == schema.TypeList {
		// TODO: proper implementation for List
		if input.Elem == nil {
			return nil, fmt.Errorf("the Elem was nil for the List type")
		}

		// either it's a List of a Simple Type
		elem, ok := input.Elem.(*schema.Schema)
		if ok {
			nested, err := frameworkResourceAttributeFromPluginSdkType(elem)
			if err != nil {
				return nil, fmt.Errorf("parsing nested object for list %+v", err)
			}

			return listAttributeFromPluginSDKv2Resource(input, nested), nil
		}

		// or it's actually a List of an Object, either a Singular or Multiple objects
		resource, ok := input.Elem.(*schema.Resource)
		if !ok {
			return nil, fmt.Errorf("the List Elem was a not *schema.Resource or *schema.Schema - got: %+v", input.Elem)
		}
		nestedAttributes := make(map[string]resourceSchema.Attribute)
		for k, v := range resource.Schema {
			nestedAttr, err := frameworkResourceAttributeFromPluginSdkType(v)
			if err != nil {
				return nil, fmt.Errorf("converting list nested schema item %q to a Framework type: %+v", k, err)
			}

			nestedAttributes[k] = nestedAttr
		}

		return listAttributeOfTypeFromPluginSDKv2Resource(input, nestedAttributes), nil
	}
	if input.Type == schema.TypeSet {
		if input.Elem == nil {
			return nil, fmt.Errorf("the Elem was nil for the Set type")
		}

		// either it's a List of a Simple Type
		elem, ok := input.Elem.(*schema.Schema)
		if ok {
			nested, err := frameworkResourceAttributeFromPluginSdkType(elem)
			if err != nil {
				return nil, fmt.Errorf("parsing nested object for Set %+v", err)
			}

			return setAttributeFromPluginSDKv2Resource(input, nested), nil
		}

		// or it's actually a Set of an Object, either a Singular or Multiple objects
		resource, ok := input.Elem.(*schema.Resource)
		if !ok {
			return nil, fmt.Errorf("the Set Elem was a not *schema.Resource or *schema.Schema - got: %+v", input.Elem)
		}
		nestedAttributes := make(map[string]resourceSchema.Attribute)
		for k, v := range resource.Schema {
			nestedAttr, err := frameworkResourceAttributeFromPluginSdkType(v)
			if err != nil {
				return nil, fmt.Errorf("converting Set nested schema item %q to a Framework type: %+v", k, err)
			}

			nestedAttributes[k] = nestedAttr
		}

		return setAttributeOfTypeFromPluginSDKv2Resource(input, nestedAttributes), nil
	}

	//if input.Type == schema.TypeList {

	//}
	//
	//if input.Type == schema.TypeSet {
	//	if input.Elem == nil {
	//		return nil, fmt.Errorf("the Elem was nil for the Set type")
	//	}
	//
	//	// either it's a List of a Simple Type
	//	elem, ok := input.Elem.(*schema.Schema)
	//	if ok {
	//		nestedElemType, err := frameworkResourceAttributeFromPluginSdkType(elem)
	//		if err != nil {
	//			return nil, fmt.Errorf("parsing nested object for Set %+v", err)
	//		}
	//
	//		attribute := resourceSchema.Attribute{
	//			Type: types.SetType{
	//				ElemType: nestedElemType.Type,
	//			},
	//			// TODO: PlanModifiers to do Min/Max Items
	//		}
	//		return mapAttribute(attribute, input), nil
	//	}
	//
	//	// or it's actually a List of an Object, either a Singular or Multiple objects
	//	resource, ok := input.Elem.(*schema.Resource)
	//	if !ok {
	//		return nil, fmt.Errorf("the List Elem was a not *schema.Resource or *schema.Schema - got: %+v", input.Elem)
	//	}
	//	nestedAttributes := make(map[string]resourceSchema.Attribute)
	//	for k, v := range resource.Schema {
	//		nestedAttr, err := frameworkResourceAttributeFromPluginSdkType(v)
	//		if err != nil {
	//			return nil, fmt.Errorf("converting list nested schema item %q to a Framework type: %+v", "TODO", err)
	//		}
	//
	//		nestedAttributes[k] = *nestedAttr
	//	}
	//
	//	attribute := resourceSchema.Attribute{
	//		Attributes: resourceSchema.SetNestedAttributes(nestedAttributes),
	//		// TODO: PlanModifiers to do Min/Max Items
	//	}
	//	if input.MaxItems == 1 {
	//		attribute.Attributes = tfsdk.SingleNestedAttributes(nestedAttributes)
	//	}
	//	return mapAttribute(attribute, input), nil
	//}

	panic(fmt.Sprintf("unsupported plugin sdk type: %+v", input.Type))
}

// TODO: start - requires impl. changes
func listAttributeFromPluginSDKv2Resource(input *schema.Schema, nested resourceSchema.Attribute) resourceSchema.Attribute {
	planModifiers := make([]planmodifier.List, 0)
	validators := make([]validator.List, 0)

	// TODO: support that ^

	return resourceSchema.ListAttribute{
		ElementType:         nested.GetType(),
		Required:            input.Required,
		Optional:            input.Optional,
		Computed:            input.Computed,
		Sensitive:           input.Sensitive,
		Description:         input.Description,
		DeprecationMessage:  input.Deprecated,
		MarkdownDescription: "",
		PlanModifiers:       planModifiers,
		Validators:          validators,
	}
}

func listAttributeOfTypeFromPluginSDKv2Resource(input *schema.Schema, nestedAttributes map[string]resourceSchema.Attribute) resourceSchema.Attribute {
	planModifiers := make([]planmodifier.List, 0)
	validators := make([]validator.List, 0)

	// TODO: support that ^

	return resourceSchema.ListNestedAttribute{
		NestedObject: resourceSchema.NestedAttributeObject{
			Attributes: nestedAttributes,
		},
		Required:            input.Required,
		Optional:            input.Optional,
		Computed:            input.Computed,
		Sensitive:           input.Sensitive,
		Description:         input.Description,
		DeprecationMessage:  input.Deprecated,
		MarkdownDescription: "",
		PlanModifiers:       planModifiers,
		Validators:          validators,
	}
}

func mapAttributeFromPluginSDKv2Resource(input *schema.Schema, nested resourceSchema.Attribute) resourceSchema.Attribute {
	planModifiers := make([]planmodifier.Map, 0)
	validators := make([]validator.Map, 0)

	// TODO: support that ^

	return resourceSchema.MapAttribute{
		ElementType:         nested.GetType(),
		Required:            input.Required,
		Optional:            input.Optional,
		Computed:            input.Computed,
		Sensitive:           input.Sensitive,
		Description:         input.Description,
		DeprecationMessage:  input.Deprecated,
		MarkdownDescription: "",
		PlanModifiers:       planModifiers,
		Validators:          validators,
	}
}
func setAttributeFromPluginSDKv2Resource(input *schema.Schema, nested resourceSchema.Attribute) resourceSchema.Attribute {
	planModifiers := make([]planmodifier.Set, 0)
	if input.DiffSuppressFunc != nil {
		planModifiers = append(planModifiers, setPlanModifierWrapper{
			diffSuppressFunc: input.DiffSuppressFunc,
		})
	}
	validators := make([]validator.Set, 0)
	if input.ValidateFunc != nil {
		validators = append(validators, setValidationWrapper{
			validateFunc: input.ValidateFunc,
		})
	}

	return resourceSchema.SetAttribute{
		ElementType:         nested.GetType(),
		Required:            input.Required,
		Optional:            input.Optional,
		Computed:            input.Computed,
		Sensitive:           input.Sensitive,
		Description:         input.Description,
		DeprecationMessage:  input.Deprecated,
		MarkdownDescription: "",
		PlanModifiers:       planModifiers,
		Validators:          validators,
	}
}
func setAttributeOfTypeFromPluginSDKv2Resource(input *schema.Schema, nestedAttributes map[string]resourceSchema.Attribute) resourceSchema.Attribute {
	planModifiers := make([]planmodifier.Set, 0)
	validators := make([]validator.Set, 0)

	// TODO: support that ^

	return resourceSchema.SetNestedAttribute{
		NestedObject: resourceSchema.NestedAttributeObject{
			Attributes: nestedAttributes,
		},
		Required:            input.Required,
		Optional:            input.Optional,
		Computed:            input.Computed,
		Sensitive:           input.Sensitive,
		Description:         input.Description,
		DeprecationMessage:  input.Deprecated,
		MarkdownDescription: "",
		PlanModifiers:       planModifiers,
		Validators:          validators,
	}
}

type setValidationWrapper struct {
	validateFunc pluginsdk.SchemaValidateFunc
}

func (setValidationWrapper) Description(_ context.Context) string {
	return ""
}

func (setValidationWrapper) MarkdownDescription(_ context.Context) string {
	return ""
}

func (w setValidationWrapper) ValidateSet(ctx context.Context, request validator.SetRequest, response *validator.SetResponse) {
	configValue := make(map[string]any, 0)
	configValueType := request.ConfigValue.ElementType(ctx)
	if configValueType.Equal(basetypes.BoolType{}) {
		var temp map[string]bool
		response.Diagnostics.Append(request.ConfigValue.ElementsAs(ctx, &temp, true)...)
		for k, v := range temp {
			configValue[k] = v
		}
	}
	if configValueType.Equal(basetypes.Float64Type{}) {
		var temp map[string]float64
		response.Diagnostics.Append(request.ConfigValue.ElementsAs(ctx, &temp, true)...)
		for k, v := range temp {
			configValue[k] = v
		}
	}
	if configValueType.Equal(basetypes.Int64Type{}) {
		var temp map[string]int64
		response.Diagnostics.Append(request.ConfigValue.ElementsAs(ctx, &temp, true)...)
		for k, v := range temp {
			configValue[k] = v
		}
	}
	if configValueType.Equal(basetypes.StringType{}) {
		var temp map[string]string
		response.Diagnostics.Append(request.ConfigValue.ElementsAs(ctx, &temp, true)...)
		for k, v := range temp {
			configValue[k] = v
		}
	}

	warnings, errs := w.validateFunc(configValue, request.Path.String())
	for _, warning := range warnings {
		response.Diagnostics.AddWarning("warning", warning)
	}
	for _, err := range errs {
		response.Diagnostics.AddError("error", err.Error())
	}
}

type setPlanModifierWrapper struct {
	diffSuppressFunc schema.SchemaDiffSuppressFunc
}

func (setPlanModifierWrapper) Description(_ context.Context) string {
	return ""
}

func (setPlanModifierWrapper) MarkdownDescription(_ context.Context) string {
	return ""
}

func (w setPlanModifierWrapper) PlanModifySet(_ context.Context, request planmodifier.SetRequest, _ *planmodifier.SetResponse) {
	// TODO: implement me
}

// TODO: end - requires impl. changes

func booleanAttributeFromPluginSDKv2Resource(input *schema.Schema) resourceSchema.Attribute {
	validators := make([]validator.Bool, 0)
	if input.ValidateFunc != nil {
		validators = append(validators, booleanValidationWrapper{
			validateFunc: input.ValidateFunc,
		})
	}

	planModifiers := make([]planmodifier.Bool, 0)
	if input.DiffSuppressFunc != nil {
		planModifiers = append(planModifiers, booleanPlanModifierWrapper{
			diffSuppress: input.DiffSuppressFunc,
		})
	}

	return &resourceSchema.BoolAttribute{
		Required:            input.Required,
		Optional:            input.Optional,
		Computed:            input.Computed,
		Sensitive:           input.Sensitive,
		Description:         input.Description,
		DeprecationMessage:  input.Deprecated,
		MarkdownDescription: "",
		PlanModifiers:       planModifiers,
		Validators:          validators,
	}
}

var _ validator.Bool = booleanValidationWrapper{}

type booleanValidationWrapper struct {
	validateFunc pluginsdk.SchemaValidateFunc
}

func (booleanValidationWrapper) Description(_ context.Context) string {
	return ""
}
func (booleanValidationWrapper) MarkdownDescription(_ context.Context) string {
	return ""
}
func (w booleanValidationWrapper) ValidateBool(_ context.Context, request validator.BoolRequest, response *validator.BoolResponse) {
	warnings, errs := w.validateFunc(request.ConfigValue.String(), request.Path.String())
	for _, warning := range warnings {
		response.Diagnostics.AddWarning("warning", warning)
	}
	for _, err := range errs {
		response.Diagnostics.AddError("error", err.Error())
	}
}

var _ planmodifier.Bool = booleanPlanModifierWrapper{}

type booleanPlanModifierWrapper struct {
	diffSuppress pluginsdk.SchemaDiffSuppressFunc
}

func (booleanPlanModifierWrapper) Description(_ context.Context) string {
	return ""
}

func (booleanPlanModifierWrapper) MarkdownDescription(_ context.Context) string {
	return ""
}

func (w booleanPlanModifierWrapper) PlanModifyBool(_ context.Context, request planmodifier.BoolRequest, _ *planmodifier.BoolResponse) {
	oldVal := ""
	if !request.StateValue.IsNull() && !request.StateValue.IsUnknown() {
		oldVal = request.StateValue.String()
	}
	newVal := ""
	if !request.ConfigValue.IsNull() && !request.ConfigValue.IsUnknown() {
		newVal = request.ConfigValue.String()
	}

	// NOTE: we don't use the `ResourceData` in any DiffSuppressFuncs, so this should, be safe
	shouldSuppressDiff := w.diffSuppress(request.Path.String(), oldVal, newVal, nil)
	if shouldSuppressDiff {
		return
	}
}

func float64AttributeFromPluginSDKv2Resource(input *schema.Schema) resourceSchema.Attribute {
	validators := make([]validator.Float64, 0)
	//if input.ValidateFunc != nil {
	//	validators = append(validators, float64ValidationWrapper{
	//		validateFunc: input.ValidateFunc,
	//	})
	//}

	planModifiers := make([]planmodifier.Float64, 0)
	//if input.DiffSuppressFunc != nil {
	//	planModifiers = append(planModifiers, float64PlanModifierWrapper{
	//		diffSuppress: input.DiffSuppressFunc,
	//	})
	//}

	return &resourceSchema.Float64Attribute{
		Required:            input.Required,
		Optional:            input.Optional,
		Computed:            input.Computed,
		Sensitive:           input.Sensitive,
		Description:         input.Description,
		DeprecationMessage:  input.Deprecated,
		MarkdownDescription: "",
		PlanModifiers:       planModifiers,
		Validators:          validators,
	}
}

var _ validator.Float64 = float64ValidationWrapper{}

type float64ValidationWrapper struct {
	validateFunc pluginsdk.SchemaValidateFunc
}

func (float64ValidationWrapper) Description(_ context.Context) string {
	return ""
}
func (float64ValidationWrapper) MarkdownDescription(_ context.Context) string {
	return ""
}
func (w float64ValidationWrapper) ValidateFloat64(_ context.Context, request validator.Float64Request, response *validator.Float64Response) {
	warnings, errs := w.validateFunc(request.ConfigValue.String(), request.Path.String())
	for _, warning := range warnings {
		response.Diagnostics.AddWarning("warning", warning)
	}
	for _, err := range errs {
		response.Diagnostics.AddError("error", err.Error())
	}
}

var _ planmodifier.Float64 = float64PlanModifierWrapper{}

type float64PlanModifierWrapper struct {
	diffSuppress pluginsdk.SchemaDiffSuppressFunc
}

func (float64PlanModifierWrapper) Description(_ context.Context) string {
	return ""
}

func (float64PlanModifierWrapper) MarkdownDescription(_ context.Context) string {
	return ""
}

func (w float64PlanModifierWrapper) PlanModifyFloat64(_ context.Context, request planmodifier.Float64Request, _ *planmodifier.Float64Response) {
	oldVal := ""
	if !request.StateValue.IsNull() && !request.StateValue.IsUnknown() {
		oldVal = request.StateValue.String()
	}
	newVal := ""
	if !request.ConfigValue.IsNull() && !request.ConfigValue.IsUnknown() {
		newVal = request.ConfigValue.String()
	}

	// NOTE: we don't use the `ResourceData` in any DiffSuppressFuncs, so this should, be safe
	shouldSuppressDiff := w.diffSuppress(request.Path.String(), oldVal, newVal, nil)
	if shouldSuppressDiff {
		return
	}
}

func int64AttributeFromPluginSDKv2Resource(input *schema.Schema) resourceSchema.Attribute {
	validators := make([]validator.Int64, 0)
	if input.ValidateFunc != nil {
		validators = append(validators, int64ValidationWrapper{
			validateFunc: input.ValidateFunc,
		})
	}

	planModifiers := make([]planmodifier.Int64, 0)
	if input.DiffSuppressFunc != nil {
		planModifiers = append(planModifiers, int64PlanModifierWrapper{
			diffSuppress: input.DiffSuppressFunc,
		})
	}

	return &resourceSchema.Int64Attribute{
		Required:            input.Required,
		Optional:            input.Optional,
		Computed:            input.Computed,
		Sensitive:           input.Sensitive,
		Description:         input.Description,
		DeprecationMessage:  input.Deprecated,
		MarkdownDescription: "",
		PlanModifiers:       planModifiers,
		Validators:          validators,
	}
}

var _ validator.Int64 = int64ValidationWrapper{}

type int64ValidationWrapper struct {
	validateFunc pluginsdk.SchemaValidateFunc
}

func (int64ValidationWrapper) Description(_ context.Context) string {
	return ""
}
func (int64ValidationWrapper) MarkdownDescription(_ context.Context) string {
	return ""
}
func (w int64ValidationWrapper) ValidateInt64(_ context.Context, request validator.Int64Request, response *validator.Int64Response) {
	warnings, errs := w.validateFunc(request.ConfigValue.String(), request.Path.String())
	for _, warning := range warnings {
		response.Diagnostics.AddWarning("warning", warning)
	}
	for _, err := range errs {
		response.Diagnostics.AddError("error", err.Error())
	}
}

var _ planmodifier.Int64 = int64PlanModifierWrapper{}

type int64PlanModifierWrapper struct {
	diffSuppress pluginsdk.SchemaDiffSuppressFunc
}

func (int64PlanModifierWrapper) Description(_ context.Context) string {
	return ""
}

func (int64PlanModifierWrapper) MarkdownDescription(_ context.Context) string {
	return ""
}

func (w int64PlanModifierWrapper) PlanModifyInt64(_ context.Context, request planmodifier.Int64Request, _ *planmodifier.Int64Response) {
	oldVal := ""
	if !request.StateValue.IsNull() && !request.StateValue.IsUnknown() {
		oldVal = request.StateValue.String()
	}
	newVal := ""
	if !request.ConfigValue.IsNull() && !request.ConfigValue.IsUnknown() {
		newVal = request.ConfigValue.String()
	}

	// NOTE: we don't use the `ResourceData` in any DiffSuppressFuncs, so this should, be safe
	shouldSuppressDiff := w.diffSuppress(request.Path.String(), oldVal, newVal, nil)
	if shouldSuppressDiff {
		return
	}
}

func stringAttributeFromPluginSDKv2Resource(input *schema.Schema) resourceSchema.Attribute {
	validators := make([]validator.String, 0)
	if input.ValidateFunc != nil {
		validators = append(validators, stringValidationWrapper{
			validateFunc: input.ValidateFunc,
		})
	}

	planModifiers := make([]planmodifier.String, 0)
	if input.DiffSuppressFunc != nil {
		planModifiers = append(planModifiers, stringPlanModifierWrapper{
			diffSuppress: input.DiffSuppressFunc,
		})
	}

	return &resourceSchema.StringAttribute{
		Required:            input.Required,
		Optional:            input.Optional,
		Computed:            input.Computed,
		Sensitive:           input.Sensitive,
		Description:         input.Description,
		DeprecationMessage:  input.Deprecated,
		MarkdownDescription: "",
		PlanModifiers:       planModifiers,
		Validators:          validators,
	}
}

var _ validator.String = stringValidationWrapper{}

type stringValidationWrapper struct {
	validateFunc pluginsdk.SchemaValidateFunc
}

func (stringValidationWrapper) Description(ctx context.Context) string {
	return ""
}
func (stringValidationWrapper) MarkdownDescription(ctx context.Context) string {
	return ""
}
func (w stringValidationWrapper) ValidateString(_ context.Context, request validator.StringRequest, response *validator.StringResponse) {
	warnings, errs := w.validateFunc(request.ConfigValue.String(), request.Path.String())
	for _, warning := range warnings {
		response.Diagnostics.AddWarning("warning", warning)
	}
	for _, err := range errs {
		response.Diagnostics.AddError("error", err.Error())
	}
}

var _ planmodifier.String = stringPlanModifierWrapper{}

type stringPlanModifierWrapper struct {
	diffSuppress pluginsdk.SchemaDiffSuppressFunc
}

func (stringPlanModifierWrapper) Description(_ context.Context) string {
	return ""
}

func (stringPlanModifierWrapper) MarkdownDescription(_ context.Context) string {
	return ""
}

func (w stringPlanModifierWrapper) PlanModifyString(_ context.Context, request planmodifier.StringRequest, _ *planmodifier.StringResponse) {
	oldVal := ""
	if !request.StateValue.IsNull() && !request.StateValue.IsUnknown() {
		oldVal = request.StateValue.String()
	}
	newVal := ""
	if !request.ConfigValue.IsNull() && !request.ConfigValue.IsUnknown() {
		newVal = request.ConfigValue.String()
	}

	// NOTE: we don't use the `ResourceData` in any DiffSuppressFuncs, so this should, be safe
	shouldSuppressDiff := w.diffSuppress(request.Path.String(), oldVal, newVal, nil)
	if shouldSuppressDiff {
		return
	}
}
