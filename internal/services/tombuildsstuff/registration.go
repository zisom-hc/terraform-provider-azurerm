package tombuildsstuff

import "github.com/hashicorp/terraform-provider-azurerm/internal/sdk"

var _ sdk.TypedServiceRegistration = Registration{}

type Registration struct {
}

func (r Registration) Name() string {
	return "Totally Fake Things"
}

func (r Registration) DataSources() []sdk.DataSource {
	return []sdk.DataSource{
		FakeDataSource{},
	}
}

func (r Registration) Resources() []sdk.Resource {
	return []sdk.Resource{}
}

func (r Registration) WebsiteCategories() []string {
	return []string{}
}
