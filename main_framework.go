//go:build framework
// +build framework

package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-provider-azurerm/internal/provider"
)

func launchProvider(debugMode bool) {
	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/hashicorp/azurerm",
		Debug:   debugMode,
	}

	err := providerserver.Serve(context.Background(), provider.AzureProvider, opts)
	if err != nil {
		log.Println(err.Error())
	}
}
