package shim

// this package contains a set of generic shims which can be used rather than referencing the Plugin SDK
// directly, it's intended to be temporary until everything is covered by the "typed sdk"

type SetsValues interface {
	Set(key string, value interface{}) error
}
