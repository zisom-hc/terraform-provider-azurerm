package helpers

import (
	"github.com/Azure/azure-sdk-for-go/services/web/mgmt/2021-03-01/web"
	"github.com/hashicorp/go-azure-helpers/lang/pointer"
)

var CorsServiceDefault = web.CorsSettings{
	AllowedOrigins:     pointer.To([]string{}),
	SupportCredentials: nil,
}
