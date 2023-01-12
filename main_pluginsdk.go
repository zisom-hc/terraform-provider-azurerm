//go:build !framework
// +build !framework

package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
	"github.com/hashicorp/terraform-provider-azurerm/internal/provider"
)

func launchProvider(debugMode bool) {
	if debugMode {
		err := plugin.Debug(context.Background(), "registry.terraform.io/hashicorp/azurerm",
			&plugin.ServeOpts{
				ProviderFunc: provider.AzureProvider,
			})
		if err != nil {
			log.Println(err.Error())
		}
	} else {
		plugin.Serve(&plugin.ServeOpts{
			ProviderFunc: provider.AzureProvider,
		})
	}
}
