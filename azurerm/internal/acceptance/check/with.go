package check

import "github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/acceptance/testclient"

type withType struct {
	thatType
}

// WithAuthMethod returns a thatType suitable for assertions, configured with a single authentication method for the client
func WithAuthMethod(authMethod testclient.AuthMethod) withType {
	return withType{
		thatType{
			authMethod: authMethod,
		},
	}
}

func (w withType) That(resourceName string) thatType {
	w.resourceName = resourceName
	r := w.thatType
	return r
}
