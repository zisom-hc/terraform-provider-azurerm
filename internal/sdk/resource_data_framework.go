//go:build framework

package sdk

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ ResourceData = &FrameworkResourceData{}

type FrameworkResourceData struct {
	ctx   context.Context
	state *tfsdk.State

	// config is the user-specified config, which isn't guaranteed to be available
	config *tfsdk.Config

	// plan is the difference between the old state and the new state
	plan *tfsdk.Plan
}

func (f *FrameworkResourceData) GetOk(key string) (interface{}, bool) {
	var out interface{}
	path := flatMapToPath(key)
	f.config.GetAttribute(f.ctx, path, &out)
	return out, out != nil
}

func (f *FrameworkResourceData) GetOkExists(key string) (interface{}, bool) {
	var out interface{}
	out = f.GetFromConfig(key)
	if out == nil {
		// TODO - This does not account for Computed values as PluginSDK does(?)
		out = f.Get(key)
	}
	return out, out != nil
}

func (f *FrameworkResourceData) HasChangesExcept(keys ...string) bool {
	if f == nil || f.plan == nil {
		return false
	}
	var state interface{}
	f.plan.Get(f.ctx, state)

	plan := state.(tfsdk.Plan)

	for attr := range plan.Schema.GetAttributes() {
		rootAttr := strings.Split(attr, ".")[0]
		var skipAttr bool

		for _, key := range keys {
			if rootAttr == key {
				skipAttr = true
				break
			}
		}
		if !skipAttr && f.HasChange(rootAttr) {
			return true
		}
	}

	return false
}

func NewFrameworkResourceData(ctx context.Context, state *tfsdk.State) *FrameworkResourceData {
	return &FrameworkResourceData{
		ctx:   ctx,
		state: state,
	}
}

// WithConfig adds the user-provided config to the ResourceData
func (f *FrameworkResourceData) WithConfig(config tfsdk.Config) {
	f.config = &config
}

// WithExistingID sets an existing known Resource ID into the state
func (f *FrameworkResourceData) WithExistingID(id string) {
	// TODO: should this be setting a local variable rather than setting it into the state?
	f.SetId(id)
}

// WithExistingState ...
func (f *FrameworkResourceData) WithExistingState(state tfsdk.State) {
	// TODO: is this just as simple as setting the passed in state?
	f.state = &state
}

// WithPlan sets an existing known Plan
func (f *FrameworkResourceData) WithPlan(plan tfsdk.Plan) {
	f.plan = &plan
}

func (f *FrameworkResourceData) Get(key string) interface{} {
	path := flatMapToPath(key)
	attrType, _ := f.state.Schema.TypeAtPath(f.ctx, path)
	switch attrType {
	case types.StringType:
		var out string
		f.state.GetAttribute(f.ctx, path, &out)
		if out != "" {
			return out
		}
	case types.MapType{}:
		out := make(map[string]interface{})
		f.state.GetAttribute(f.ctx, path, &out)
		if len(out) != 0 {
			return out
		}
	default:
		if _, ok := attrType.(types.MapType); ok {
			switch attrType.(types.MapType).ElemType {
			case types.StringType:
				out := make(map[string]string)
				f.state.GetAttribute(f.ctx, path, &out)
				if len(out) != 0 {
					return out
				}
			}
		}
	}

	return nil
}

func (f *FrameworkResourceData) GetChange(key string) (original interface{}, updated interface{}) {
	path := flatMapToPath(key)
	var oldVal interface{}
	if f.plan != nil {
		diag := f.plan.GetAttribute(f.ctx, path, &oldVal)
		if diag == nil {
			original = oldVal
		}
	} else if f.state != nil {
		diag := f.state.GetAttribute(f.ctx, path, &oldVal)
		if diag == nil {
			original = oldVal
		}
	}

	var newVal interface{}
	diag := f.config.GetAttribute(f.ctx, path, &newVal)
	if diag == nil {
		updated = newVal
	}
	return
}

func (f *FrameworkResourceData) GetFromConfig(key string) interface{} {
	if f.config == nil {
		return nil
	}
	path := flatMapToPath(key)
	attrType, _ := f.config.Schema.TypeAtPath(f.ctx, path)
	switch attrType {
	case types.StringType:
		var out string
		f.config.GetAttribute(f.ctx, path, &out)
		if out != "" {
			return out
		}
	case types.BoolType:
		var out bool
		f.config.GetAttribute(f.ctx, path, &out)
		return out

	case types.Float64Type:
		var out float64
		f.config.GetAttribute(f.ctx, path, &out)
		if out != 0 {
			return out
		}
	case types.Int64Type:
		var out int64
		f.config.GetAttribute(f.ctx, path, &out)
		if out != 0 {
			return out
		}
	case types.NumberType:
		// TODO?

	default:
		// Deal with non-primitives here
		if _, ok := attrType.(types.MapType); ok {
			switch attrType.(types.MapType).ElemType {
			case types.StringType:
				out := make(map[string]string)
				f.config.GetAttribute(f.ctx, path, &out)
				if len(out) != 0 {
					return out
				}
			case types.BoolType:
				// TODO?
			case types.Float64Type:
				// TODO?
			case types.Int64Type:
				// TODO?
			case types.NumberType:
				// TODO?
			}

		}
		if _, ok := attrType.(types.ListType); ok {
			// TODO
		}
		if _, ok := attrType.(types.SetType); ok {
			// TODO
		}
	}
	return nil
}

func (f *FrameworkResourceData) GetFromState(key string) interface{} {
	return f.Get(key)
}

func (f *FrameworkResourceData) HasChange(key string) bool {
	n, o := f.GetChange(key)
	return !cmp.Equal(n, o)
}

func (f *FrameworkResourceData) HasChanges(keys ...string) bool {
	for _, k := range keys {
		if f.HasChange(k) {
			return true
		}
	}

	return false
}

func (f *FrameworkResourceData) Id() string {
	return f.Get("id").(string)
}

func (f *FrameworkResourceData) Set(key string, value interface{}) error {
	path := flatMapToPath(key)
	d := f.state.SetAttribute(f.ctx, path, value)
	if d.HasError() {
		// TODO: until Error() is implemented
		s := make([]string, 0)
		for _, e := range d {
			s = append(s, fmt.Sprintf("%s: %s", e.Summary(), e.Detail()))
		}

		return fmt.Errorf("setting attribute %q:\n\n", strings.Join(s, "\n\n"))
	}
	return nil
}

func (f *FrameworkResourceData) SetConnInfo(v map[string]string) {
	//TODO implement me
	panic("implement me")
}

func (f *FrameworkResourceData) SetId(id string) {
	if id == "" {
		f.state.RemoveResource(f.ctx)
	} else {
		f.Set("id", id)
	}
}

func flatMapToPath(key string) path.Path {
	// TODO: implement this properly
	return path.Root(key)
}
