package sdk

type ResourceData interface {
	// Get returns a value from either the config/state depending on where this is called
	// in Create and Update functions this will return from the config
	// in Read, Exists and Import functions this will return from the state
	// NOTE: this should not be called from Delete functions.
	Get(key string) interface{}

	GetOk(key string) (interface{}, bool)

	GetOkExists(key string) (interface{}, bool)

	GetFromConfig(key string) interface{}

	GetFromState(key string) interface{}

	GetChange(key string) (interface{}, interface{})

	HasChange(key string) bool

	HasChanges(keys ...string) bool

	HasChangesExcept(keys ...string) bool

	Id() string

	// NOTE: this intentionally doesn't implement IsNewResource since we should be splitting Create and Update methods

	Set(key string, value interface{}) error

	SetConnInfo(v map[string]string)

	SetId(id string)

	// TODO: add Get/Set helpers for each type

	//GetString(key string) * string
}
