package hpccache

import (
	"context"
	"fmt"
	"github.com/hashicorp/go-azure-helpers/lang/response"
	"github.com/hashicorp/go-azure-sdk/resource-manager/storagecache/2021-09-01/caches"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/storagecache/mgmt/2021-09-01/storagecache" // nolint: staticcheck
	"github.com/hashicorp/terraform-provider-azurerm/internal/tf/pluginsdk"
)

func getAccessPolicyByName(policies []caches.NfsAccessPolicy, name string) *caches.NfsAccessPolicy {
	for _, policy := range policies {
		if policy.Name == name {
			return &policy
		}
	}
	return nil
}

func deleteAccessPolicyByName(policies []storagecache.NfsAccessPolicy, name string) []storagecache.NfsAccessPolicy {
	newPolicies := make([]storagecache.NfsAccessPolicy, 0)
	for _, policy := range policies {
		if policy.Name != nil && *policy.Name != name {
			newPolicies = append(newPolicies, policy)
		}
	}
	return newPolicies
}

func CacheInsertOrUpdateAccessPolicy(policies []storagecache.NfsAccessPolicy, policy storagecache.NfsAccessPolicy) ([]storagecache.NfsAccessPolicy, error) {
	if policy.Name == nil {
		return nil, fmt.Errorf("the name of the HPC Cache access policy is nil")
	}

	newPolicies := make([]storagecache.NfsAccessPolicy, 0)
	isNew := true
	for _, existPolicy := range policies {
		if existPolicy.Name != nil && *existPolicy.Name == *policy.Name {
			newPolicies = append(newPolicies, policy)
			isNew = false
			continue
		}
		newPolicies = append(newPolicies, existPolicy)
	}

	if !isNew {
		return newPolicies, nil
	}

	return append(newPolicies, policy), nil
}

func resourceHPCCacheWaitForCreating(ctx context.Context, client *caches.CachesClient, id caches.CacheId) (*storagecache.Cache, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, fmt.Errorf("internal-error: context had no deadline")
	}
	state := &pluginsdk.StateChangeConf{
		MinTimeout: 30 * time.Second,
		Delay:      10 * time.Second,
		Pending:    []string{string(storagecache.ProvisioningStateTypeCreating)},
		Target:     []string{string(storagecache.ProvisioningStateTypeSucceeded)},
		Refresh:    resourceHPCCacheRefresh(ctx, client, id),
		Timeout:    time.Until(deadline),
	}

	resp, err := state.WaitForStateContext(ctx)
	if err != nil {
		cache := resp.(storagecache.Cache)
		return &cache, err
	}

	cache := resp.(storagecache.Cache)
	return &cache, nil
}

func resourceHPCCacheRefresh(ctx context.Context, client *caches.CachesClient, id caches.CacheId) pluginsdk.StateRefreshFunc {
	return func() (interface{}, string, error) {
		resp, err := client.Get(ctx, id)
		if err != nil {
			if response.WasNotFound(resp.HttpResponse) {
				return resp, "NotFound", nil
			}

			return resp, "Error", fmt.Errorf("retrieving %s: %+v", id, err)
		}

		if resp.Model == nil || resp.Model.Properties == nil {
			return resp, "Error", fmt.Errorf("retrieving %s: model was nil", id)
		}
		if resp.Model.Properties.ProvisioningState == nil {
			return resp, "Error", fmt.Errorf("retrieving %s: `properties.provisioningState` was nil", id)
		}
		return resp, string(*resp.Model.Properties.ProvisioningState), nil
	}
}
