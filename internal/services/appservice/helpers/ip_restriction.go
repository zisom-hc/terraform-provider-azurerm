package helpers

import (
	"reflect"

	"github.com/Azure/azure-sdk-for-go/services/web/mgmt/2021-03-01/web"
	"github.com/hashicorp/go-azure-helpers/lang/pointer"
)

var IpRestrictionAllowPublicAccess = IpRestriction{
	IpAddress:    "Any",
	ServiceTag:   "",
	VnetSubnetId: "",
	Name:         "Allow all",
	Priority:     2147483647,
	Action:       "Allow",
	Headers:      []IpRestrictionHeaders{},
}

var IpRestrictionServiceDefault = web.IPSecurityRestriction{
	Name:        pointer.To("Allow all"),
	IPAddress:   pointer.To("Any"),
	Action:      pointer.To("Allow"),
	Priority:    pointer.To(int32(2147483647)),
	Description: pointer.To("Allow all access"),
}

func ipRestrictionIsDefaultPublic(input []IpRestriction) bool {
	return reflect.DeepEqual(input, []IpRestriction{IpRestrictionAllowPublicAccess})
}
