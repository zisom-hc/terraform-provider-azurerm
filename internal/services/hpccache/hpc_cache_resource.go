package hpccache

import (
	"context"
	"fmt"
	"github.com/hashicorp/go-azure-helpers/lang/pointer"
	"github.com/hashicorp/go-azure-helpers/resourcemanager/location"
	"log"
	"regexp"
	"strconv"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/storagecache/mgmt/2021-09-01/storagecache" // nolint: staticcheck
	"github.com/hashicorp/go-azure-helpers/lang/response"
	"github.com/hashicorp/go-azure-helpers/resourcemanager/commonschema"
	"github.com/hashicorp/go-azure-helpers/resourcemanager/identity"
	"github.com/hashicorp/go-azure-helpers/resourcemanager/tags"
	"github.com/hashicorp/go-azure-sdk/resource-manager/storagecache/2021-09-01/caches"
	"github.com/hashicorp/terraform-provider-azurerm/helpers/azure"
	"github.com/hashicorp/terraform-provider-azurerm/helpers/tf"
	"github.com/hashicorp/terraform-provider-azurerm/internal/clients"
	"github.com/hashicorp/terraform-provider-azurerm/internal/services/keyvault/client"
	keyVaultParse "github.com/hashicorp/terraform-provider-azurerm/internal/services/keyvault/parse"
	keyVaultValidate "github.com/hashicorp/terraform-provider-azurerm/internal/services/keyvault/validate"
	"github.com/hashicorp/terraform-provider-azurerm/internal/services/network/validate"
	resourcesClient "github.com/hashicorp/terraform-provider-azurerm/internal/services/resource/client"
	"github.com/hashicorp/terraform-provider-azurerm/internal/tf/pluginsdk"
	"github.com/hashicorp/terraform-provider-azurerm/internal/tf/validation"
	"github.com/hashicorp/terraform-provider-azurerm/internal/timeouts"
	"github.com/hashicorp/terraform-provider-azurerm/utils"
)

func resourceHPCCache() *pluginsdk.Resource {
	return &pluginsdk.Resource{
		Create: resourceHPCCacheCreateOrUpdate,
		Update: resourceHPCCacheCreateOrUpdate,
		Read:   resourceHPCCacheRead,
		Delete: resourceHPCCacheDelete,

		Timeouts: &pluginsdk.ResourceTimeout{
			Create: pluginsdk.DefaultTimeout(60 * time.Minute),
			Update: pluginsdk.DefaultTimeout(60 * time.Minute),
			Read:   pluginsdk.DefaultTimeout(5 * time.Minute),
			Delete: pluginsdk.DefaultTimeout(60 * time.Minute),
		},
		Importer: pluginsdk.ImporterValidatingResourceId(func(id string) error {
			_, err := caches.ParseCacheID(id)
			return err
		}),

		Schema: resourceHPCCacheSchema(),
	}
}

func resourceHPCCacheCreateOrUpdate(d *pluginsdk.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).HPCCache.CachesClient
	keyVaultsClient := meta.(*clients.Client).KeyVault
	resourcesClient := meta.(*clients.Client).Resource
	subscriptionId := meta.(*clients.Client).Account.SubscriptionId
	ctx, cancel := timeouts.ForCreate(meta.(*clients.Client).StopContext, d)
	defer cancel()

	id := caches.NewCacheID(subscriptionId, d.Get("resource_group_name").(string), d.Get("name").(string))
	if d.IsNewResource() {
		existing, err := client.Get(ctx, id)
		if err != nil {
			if !response.WasNotFound(existing.HttpResponse) {
				return fmt.Errorf("checking for presence of existing HPC Cache %q: %s", id, err)
			}
		}

		if !response.WasNotFound(existing.HttpResponse) {
			return tf.ImportAsExistsError("azurerm_hpc_cache", id.ID())
		}
	}

	location := d.Get("location").(string)
	cacheSize := d.Get("cache_size_in_gb").(int)
	subnet := d.Get("subnet_id").(string)
	skuName := d.Get("sku_name").(string)

	// SKU Cache Combo Validation
	switch {
	case skuName == "Standard_L4_5G" && cacheSize != 21623:
		return fmt.Errorf("The Standard_L4_5G SKU only supports a cache size of 21623")
	case skuName == "Standard_L9G" && cacheSize != 43246:
		return fmt.Errorf("The Standard_L9G SKU only supports a cache size of 43246")
	case skuName == "Standard_L16G" && cacheSize != 86491:
		return fmt.Errorf("The Standard_L16G SKU only supports a cache size of 86491")
	case (cacheSize == 21623 || cacheSize == 43246 || cacheSize == 86491) && (skuName == "Standard_2G" || skuName == "Standard_4G" || skuName == "Standard_8G"):
		return fmt.Errorf("Incompatible cache size chosen. 21623, 43246 and 86491 are reserved for Read Only resources.")
	}

	var accessPolicies []storagecache.NfsAccessPolicy
	if !d.IsNewResource() {
		existing, err := client.Get(ctx, id)
		if err != nil {
			return fmt.Errorf("retrieving existing HPC Cache %q: %v", id, err)
		}
		if prop := existing.CacheProperties; prop != nil {
			if settings := existing.SecuritySettings; settings != nil {
				if policies := settings.AccessPolicies; policies != nil {
					accessPolicies = *policies
				}
			}
		}
	}
	defaultAccessPolicy := expandStorageCacheDefaultAccessPolicy(d.Get("default_access_policy").([]interface{}))
	if defaultAccessPolicy != nil {
		var err error
		accessPolicies, err = CacheInsertOrUpdateAccessPolicy(accessPolicies, *defaultAccessPolicy)
		if err != nil {
			return err
		}
	}

	directorySetting := expandStorageCacheDirectorySettings(d)

	identity, err := identity.ExpandSystemAndUserAssignedMap(d.Get("identity").([]interface{}))
	if err != nil {
		return fmt.Errorf("expanding `identity`: %+v", err)
	}

	payload := caches.Cache{
		Location: utils.String(location),
		Properties: &caches.CacheProperties{
			CacheSizeGB:     utils.Int64(int64(cacheSize)),
			Subnet:          utils.String(subnet),
			NetworkSettings: expandStorageCacheNetworkSettings(d),
			SecuritySettings: &caches.CacheSecuritySettings{
				AccessPolicies: &accessPolicies,
			},
			DirectoryServicesSettings: directorySetting,
		},
		Sku: &caches.CacheSku{
			Name: utils.String(skuName),
		},
		Identity: identity,
		Tags:     tags.Expand(d.Get("tags").(map[string]interface{})),
	}

	if !d.IsNewResource() {
		oldKeyVaultKeyId, newKeyVaultKeyId := d.GetChange("key_vault_key_id")
		if (oldKeyVaultKeyId.(string) != "" && newKeyVaultKeyId.(string) == "") || (oldKeyVaultKeyId.(string) == "" && newKeyVaultKeyId.(string) != "") {
			return fmt.Errorf("`key_vault_key_id` can not be added or removed after HPC Cache is created")
		}
	}

	requireAdditionalUpdate := false
	if v, ok := d.GetOk("key_vault_key_id"); ok {
		autoKeyRotationEnabled := d.Get("automatically_rotate_key_to_latest_enabled").(bool)
		if !d.IsNewResource() && d.HasChange("key_vault_key_id") && autoKeyRotationEnabled {
			// It is by design that `automatically_rotate_key_to_latest_enabled` changes to `false` when `key_vault_key_id` is changed, needs to do an additional update to set it back
			requireAdditionalUpdate = true
		}
		// For new created resource `automatically_rotate_key_to_latest_enabled` needs an additional update to set it to true to.
		if d.IsNewResource() && autoKeyRotationEnabled {
			requireAdditionalUpdate = true
		}

		keyVaultKeyId := v.(string)
		keyVaultDetails, err := storageCacheRetrieveKeyVault(ctx, keyVaultsClient, resourcesClient, keyVaultKeyId)
		if err != nil {
			return fmt.Errorf("validating Key Vault Key %q for HPC Cache: %+v", keyVaultKeyId, err)
		}
		if azure.NormalizeLocation(keyVaultDetails.location) != azure.NormalizeLocation(location) {
			return fmt.Errorf("validating Key Vault %q (Resource Group %q) for HPC Cache: Key Vault must be in the same region as HPC Cache!", keyVaultDetails.keyVaultName, keyVaultDetails.resourceGroupName)
		}
		if !keyVaultDetails.softDeleteEnabled {
			return fmt.Errorf("validating Key Vault %q (Resource Group %q) for HPC Cache: Soft Delete must be enabled but it isn't!", keyVaultDetails.keyVaultName, keyVaultDetails.resourceGroupName)
		}
		if !keyVaultDetails.purgeProtectionEnabled {
			return fmt.Errorf("validating Key Vault %q (Resource Group %q) for HPC Cache: Purge Protection must be enabled but it isn't!", keyVaultDetails.keyVaultName, keyVaultDetails.resourceGroupName)
		}

		payload.CacheProperties.EncryptionSettings = &storagecache.CacheEncryptionSettings{
			KeyEncryptionKey: &storagecache.KeyVaultKeyReference{
				KeyURL: utils.String(keyVaultKeyId),
				SourceVault: &storagecache.KeyVaultKeyReferenceSourceVault{
					ID: utils.String(keyVaultDetails.keyVaultId),
				},
			},
			RotationToLatestKeyVersionEnabled: utils.Bool(autoKeyRotationEnabled),
		}
	}

	if err := client.CreateOrUpdateThenPoll(ctx, id, payload); err != nil {
		return fmt.Errorf("creating/updating %s: %+v", id, err)
	}

	if requireAdditionalUpdate {
		if err := client.CreateOrUpdateThenPoll(ctx, id, payload); err != nil {
			return fmt.Errorf("updating %s: %+v", id, err)
		}
	}

	// If any directory setting is set, we'll further check either the `usernameDownloaded` (for LDAP/Flat File), or the `domainJoined` (for AD) in response to ensure the configuration is correct, and the cache is functional.
	// There are situations that the LRO succeeded, whilst ends up with a non-functional cache (e.g. providing some invalid flat file setting).
	if directorySetting != nil {
		resp, err := client.Get(ctx, id)
		if err != nil {
			return fmt.Errorf("retrieving %s: %+v", id, err)
		}

		prop := resp.CacheProperties
		if prop == nil {
			return fmt.Errorf("Unepxected nil `cacheProperties` in response")
		}
		ds := prop.DirectoryServicesSettings
		if ds == nil {
			return fmt.Errorf("Unexpected nil `directoryServicesSettings` in response")
		}

		// In case the user uses active directory service, we
		if directorySetting.ActiveDirectory != nil {
			ad := ds.ActiveDirectory
			if ad == nil {
				return fmt.Errorf("Unexpected nil `activeDirectory` in response")
			}
			if ad.DomainJoined != storagecache.DomainJoinedTypeYes {
				return fmt.Errorf("failed to join domain, current status: %s", ad.DomainJoined)
			}
		} else {
			ud := ds.UsernameDownload
			if ud == nil {
				return fmt.Errorf("Unexpected nil `usernameDownload` in response")
			}
			if ud.UsernameDownloaded != storagecache.UsernameDownloadedTypeYes {
				return fmt.Errorf("failed to download directory info, current status: %s", ud.UsernameDownloaded)
			}
		}
	}

	// wait for HPC Cache provision state to be succeeded. or further operations with it may fail.
	if _, err = resourceHPCCacheWaitForCreating(ctx, client, id); err != nil {
		return fmt.Errorf("waiting for %s to finish creating: %+v", id, err)
	}

	d.SetId(id.ID())
	return resourceHPCCacheRead(d, meta)
}

func resourceHPCCacheRead(d *pluginsdk.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).HPCCache.CachesClient
	ctx, cancel := timeouts.ForRead(meta.(*clients.Client).StopContext, d)
	defer cancel()

	id, err := caches.ParseCacheID(d.Id())
	if err != nil {
		return err
	}

	resp, err := client.Get(ctx, *id)
	if err != nil {
		if response.WasNotFound(resp.HttpResponse) {
			log.Printf("[DEBUG] %s was not found - removing from state!", *id)
			d.SetId("")
			return nil
		}

		return fmt.Errorf("retrieving %s: %+v", *id, err)
	}

	d.Set("name", id.CacheName)
	d.Set("resource_group_name", id.ResourceGroupName)

	if model := resp.Model; model != nil {
		d.Set("location", location.NormalizeNilable(model.Location))

		if props := model.Properties; props != nil {
			d.Set("cache_size_in_gb", props.CacheSizeGB)
			d.Set("subnet_id", props.Subnet)
			d.Set("mount_addresses", utils.FlattenStringSlice(props.MountAddresses))

			mtu, ntpServer, dnsSetting := flattenStorageCacheNetworkSettings(props.NetworkSettings)
			d.Set("mtu", mtu)
			d.Set("ntp_server", ntpServer)
			if err := d.Set("dns", dnsSetting); err != nil {
				return fmt.Errorf("setting `dns`: %v", err)
			}

			flattenedActiveDirectorySettings := flattenActiveDirectorySettings(props.DirectoryServicesSettings, d.Get("directory_active_directory").([]interface{}))
			if err := d.Set("directory_active_directory", flattenedActiveDirectorySettings); err != nil {
				return fmt.Errorf("setting `directory_active_directory`: %v", err)
			}

			flattenedFileSettings := flattenFileSettings(props.DirectoryServicesSettings)
			if err := d.Set("directory_flat_file", flattenedFileSettings); err != nil {
				return fmt.Errorf("setting `directory_flat_file`: %v", err)
			}

			flattenedLDAPSettings := flattenLDAPSettings(props.DirectoryServicesSettings, d.Get("directory_ldap").([]interface{}))
			if err := d.Set("directory_ldap", flattenedLDAPSettings); err != nil {
				return fmt.Errorf("setting `directory_ldap`: %v", err)
			}

			defaultAccessPolicy := make([]interface{}, 0)
			if securitySettings := props.SecuritySettings; securitySettings != nil {
				if securitySettings.AccessPolicies != nil {
					defaultPolicy := getAccessPolicyByName(*securitySettings.AccessPolicies, "default")
					if defaultPolicy != nil {
						defaultAccessPolicy, err = flattenStorageCacheNfsDefaultAccessPolicy(*defaultPolicy)
						if err != nil {
							return err
						}
					}
				}
			}
			if err := d.Set("default_access_policy", defaultAccessPolicy); err != nil {
				return fmt.Errorf("setting `default_access_policy`: %v", err)
			}

			keyVaultKeyId := ""
			autoKeyRotationEnabled := false
			if encryptionSettings := props.EncryptionSettings; encryptionSettings != nil {
				if encryptionSettings.KeyEncryptionKey != nil {
					keyVaultKeyId = encryptionSettings.KeyEncryptionKey.KeyUrl
				}
				if encryptionSettings.RotationToLatestKeyVersionEnabled != nil {
					autoKeyRotationEnabled = *encryptionSettings.RotationToLatestKeyVersionEnabled
				}
			}
			d.Set("key_vault_key_id", keyVaultKeyId)
			d.Set("automatically_rotate_key_to_latest_enabled", autoKeyRotationEnabled)
		}

		skuName := ""
		if sku := model.Sku; sku != nil {
			skuName = *sku.Name
		}
		d.Set("sku_name", skuName)

		identity, err := identity.FlattenSystemAndUserAssignedMap(model.Identity)
		if err != nil {
			return err
		}
		if err := d.Set("identity", identity); err != nil {
			return fmt.Errorf("setting `identity`: %+v", err)
		}

		if err := tags.FlattenAndSet(d, model.Tags); err != nil {
			return fmt.Errorf("setting `tags`: %+v", err)
		}
	}

	return nil
}

func resourceHPCCacheDelete(d *pluginsdk.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).HPCCache.CachesClient
	ctx, cancel := timeouts.ForDelete(meta.(*clients.Client).StopContext, d)
	defer cancel()

	id, err := caches.ParseCacheID(d.Id())
	if err != nil {
		return err
	}

	if err := client.DeleteThenPoll(ctx, *id); err != nil {
		return fmt.Errorf("deleting %s: %+v", *id, err)
	}

	return nil
}

func expandStorageCacheDefaultAccessPolicy(input []interface{}) *storagecache.NfsAccessPolicy {
	if len(input) == 0 {
		return nil
	}

	return &storagecache.NfsAccessPolicy{
		Name:        utils.String("default"),
		AccessRules: expandStorageCacheNfsAccessRules(input[0].(map[string]interface{})["access_rule"].(*pluginsdk.Set).List()),
	}
}

func flattenStorageCacheNfsDefaultAccessPolicy(input caches.NfsAccessPolicy) ([]interface{}, error) {
	rules, err := flattenStorageCacheNfsAccessRules(input.AccessRules)
	if err != nil {
		return nil, err
	}

	return []interface{}{
		map[string]interface{}{
			"access_rule": rules,
		},
	}, nil
}

func expandStorageCacheNfsAccessRules(input []interface{}) *[]storagecache.NfsAccessRule {
	var out []storagecache.NfsAccessRule
	for _, accessRuleRaw := range input {
		b := accessRuleRaw.(map[string]interface{})
		out = append(out, storagecache.NfsAccessRule{
			Scope:          storagecache.NfsAccessRuleScope(b["scope"].(string)),
			Access:         storagecache.NfsAccessRuleAccess(b["access"].(string)),
			Filter:         utils.String(b["filter"].(string)),
			Suid:           utils.Bool(b["suid_enabled"].(bool)),
			SubmountAccess: utils.Bool(b["submount_access_enabled"].(bool)),
			RootSquash:     utils.Bool(b["root_squash_enabled"].(bool)),
			AnonymousUID:   utils.String(strconv.Itoa(b["anonymous_uid"].(int))),
			AnonymousGID:   utils.String(strconv.Itoa(b["anonymous_gid"].(int))),
		})
	}
	return &out
}

func flattenStorageCacheNfsAccessRules(input []caches.NfsAccessRule) ([]interface{}, error) {
	rules := make([]interface{}, 0)
	for _, accessRule := range input {
		filter := ""
		if accessRule.Filter != nil {
			filter = *accessRule.Filter
		}

		suidEnabled := false
		if accessRule.Suid != nil {
			suidEnabled = *accessRule.Suid
		}

		submountAccessEnabled := false
		if accessRule.SubmountAccess != nil {
			submountAccessEnabled = *accessRule.SubmountAccess
		}

		rootSquashEnabled := false
		if accessRule.RootSquash != nil {
			rootSquashEnabled = *accessRule.RootSquash
		}

		anonymousUID := 0
		if accessRule.AnonymousUID != nil {
			var err error
			anonymousUID, err = strconv.Atoi(*accessRule.AnonymousUID)
			if err != nil {
				return nil, fmt.Errorf("converting `anonymous_uid` from string to int")
			}
		}

		anonymousGID := 0
		if accessRule.AnonymousGID != nil {
			var err error
			anonymousGID, err = strconv.Atoi(*accessRule.AnonymousGID)
			if err != nil {
				return nil, fmt.Errorf("converting `anonymous_gid` from string to int")
			}
		}

		rules = append(rules, map[string]interface{}{
			"scope":                   accessRule.Scope,
			"access":                  accessRule.Access,
			"filter":                  filter,
			"suid_enabled":            suidEnabled,
			"submount_access_enabled": submountAccessEnabled,
			"root_squash_enabled":     rootSquashEnabled,
			"anonymous_uid":           anonymousUID,
			"anonymous_gid":           anonymousGID,
		})
	}

	return rules, nil
}

func expandStorageCacheNetworkSettings(d *pluginsdk.ResourceData) *caches.CacheNetworkSettings {
	out := &caches.CacheNetworkSettings{
		Mtu:       pointer.To(int64(d.Get("mtu").(int))),
		NtpServer: pointer.To(d.Get("ntp_server").(string)),
	}

	if dnsSetting, ok := d.GetOk("dns"); ok {
		setting := dnsSetting.([]interface{})[0].(map[string]interface{})
		out.DnsServers = utils.ExpandStringSlice(setting["servers"].([]interface{}))
		searchDomain := setting["search_domain"].(string)
		if searchDomain != "" {
			out.DnsSearchDomain = &searchDomain
		}
	}
	return out
}

func flattenStorageCacheNetworkSettings(settings *caches.CacheNetworkSettings) (mtu int, ntpServer string, dnsSetting []interface{}) {
	if settings == nil {
		return
	}

	if settings.Mtu != nil {
		mtu = int(*settings.Mtu)
	}

	if settings.NtpServer != nil {
		ntpServer = *settings.NtpServer
	}

	if settings.DnsServers != nil {
		dnsServers := utils.FlattenStringSlice(settings.DnsServers)

		searchDomain := ""
		if settings.DnsSearchDomain != nil {
			searchDomain = *settings.DnsSearchDomain
		}

		dnsSetting = []interface{}{
			map[string]interface{}{
				"servers":       dnsServers,
				"search_domain": searchDomain,
			},
		}
	}
	return
}

func expandStorageCacheDirectorySettings(d *pluginsdk.ResourceData) *caches.CacheDirectorySettings {
	if raw := d.Get("directory_active_directory").([]interface{}); len(raw) != 0 {
		b := raw[0].(map[string]interface{})

		var secondaryDNSPtr *string
		if secondaryDNS := b["dns_secondary_ip"].(string); secondaryDNS != "" {
			secondaryDNSPtr = &secondaryDNS
		}

		return &caches.CacheDirectorySettings{
			UsernameDownload: &caches.CacheUsernameDownloadSettings{
				ExtendedGroups: utils.Bool(true),
				UsernameSource: caches.UsernameSourceAD,
			},
			ActiveDirectory: &caches.CacheActiveDirectorySettings{
				PrimaryDnsIPAddress:   utils.String(b["dns_primary_ip"].(string)),
				SecondaryDnsIPAddress: secondaryDNSPtr,
				DomainName:            utils.String(b["domain_name"].(string)),
				CacheNetBiosName:      utils.String(b["cache_netbios_name"].(string)),
				DomainNetBiosName:     utils.String(b["domain_netbios_name"].(string)),
				Credentials: &caches.CacheActiveDirectorySettingsCredentials{
					Username: utils.String(b["username"].(string)),
					Password: utils.String(b["password"].(string)),
				},
			},
		}
	}

	if raw := d.Get("directory_flat_file").([]interface{}); len(raw) != 0 {
		b := raw[0].(map[string]interface{})
		return &caches.CacheDirectorySettings{
			UsernameDownload: &caches.CacheUsernameDownloadSettings{
				ExtendedGroups: utils.Bool(true),
				UsernameSource: caches.UsernameSourceFile,
				GroupFileURI:   utils.String(b["group_file_uri"].(string)),
				UserFileURI:    utils.String(b["password_file_uri"].(string)),
			},
		}
	}

	if raw := d.Get("directory_ldap").([]interface{}); len(raw) != 0 {
		b := raw[0].(map[string]interface{})
		var certValidationUriPtr *string
		certValidationUri := b["certificate_validation_uri"].(string)
		if certValidationUri != "" {
			certValidationUriPtr = &certValidationUri
		}
		return &caches.CacheDirectorySettings{
			UsernameDownload: &caches.CacheUsernameDownloadSettings{
				ExtendedGroups:          utils.Bool(true),
				UsernameSource:          storagecache.UsernameSourceLDAP,
				LdapServer:              utils.String(b["server"].(string)),
				LdapBaseDN:              utils.String(b["base_dn"].(string)),
				EncryptLdapConnection:   utils.Bool(b["encrypted"].(bool)),
				RequireValidCertificate: utils.Bool(certValidationUriPtr != nil),
				AutoDownloadCertificate: utils.Bool(b["download_certificate_automatically"].(bool)),
				CaCertificateURI:        certValidationUriPtr,
				Credentials:             expandStorageCacheDirectoryLdapBind(b["bind"].([]interface{})),
			},
		}
	}

	return nil
}

func flattenActiveDirectorySettings(input *caches.CacheDirectorySettings, existing []interface{}) []interface{} {
	output := make([]interface{}, 0)

	if input != nil && input.UsernameDownload != nil && input.UsernameDownload.UsernameSource != nil && *input.UsernameDownload.UsernameSource == caches.UsernameSourceAD {
		if ad := input.ActiveDirectory; ad != nil {
			secondaryDNSIPAddress := ""
			if ad.SecondaryDnsIPAddress != nil {
				secondaryDNSIPAddress = *ad.SecondaryDnsIPAddress
			}

			username := ""
			password := ""
			// Since the credentials are never returned from response. We will set whatever specified in the config back to state as the best effort.
			if len(existing) == 1 {
				if val, ok := existing[0].(map[string]interface{}); ok {
					username = val["username"].(string)
					password = val["password"].(string)
				}
			}

			output = append(output, map[string]interface{}{
				"dns_primary_ip":      ad.PrimaryDnsIPAddress,
				"domain_name":         ad.DomainName,
				"cache_netbios_name":  ad.CacheNetBiosName,
				"domain_netbios_name": ad.DomainNetBiosName,
				"dns_secondary_ip":    secondaryDNSIPAddress,
				"username":            username,
				"password":            password,
			})
		}
	}

	return output
}

func flattenFileSettings(input *caches.CacheDirectorySettings) []interface{} {
	output := make([]interface{}, 0)

	if input != nil && input.UsernameDownload != nil && input.UsernameDownload.UsernameSource != nil && *input.UsernameDownload.UsernameSource == caches.UsernameSourceFile {
		groupFileUri := ""
		if input.UsernameDownload.GroupFileURI != nil {
			groupFileUri = *input.UsernameDownload.GroupFileURI
		}

		passwdFileUri := ""
		if input.UsernameDownload.UserFileURI != nil {
			passwdFileUri = *input.UsernameDownload.UserFileURI
		}

		output = append(output, map[string]interface{}{
			"group_file_uri":    groupFileUri,
			"password_file_uri": passwdFileUri,
		})
	}

	return output
}

func flattenLDAPSettings(input *caches.CacheDirectorySettings, existing []interface{}) []interface{} {
	output := make([]interface{}, 0)

	if input != nil && input.UsernameDownload != nil && input.UsernameDownload.UsernameSource != nil && *input.UsernameDownload.UsernameSource == caches.UsernameSourceLDAP {
		var server string
		if input.UsernameDownload.LdapServer != nil {
			server = *input.UsernameDownload.LdapServer
		}

		var baseDn string
		if input.UsernameDownload.LdapBaseDN != nil {
			baseDn = *input.UsernameDownload.LdapBaseDN
		}

		connEncrypted := false
		if input.UsernameDownload.EncryptLdapConnection != nil {
			connEncrypted = *input.UsernameDownload.EncryptLdapConnection
		}

		certValidationUri := ""
		if input.UsernameDownload.CaCertificateURI != nil {
			certValidationUri = *input.UsernameDownload.CaCertificateURI
		}

		autoDownloadCert := false
		if input.UsernameDownload.AutoDownloadCertificate != nil {
			autoDownloadCert = *input.UsernameDownload.AutoDownloadCertificate
		}

		bind := make([]interface{}, 0)
		// Since the credentials are never returned from response. We will set whatever specified in the config back to state as the best effort.
		if len(existing) == 1 {
			if item, ok := existing[0].(map[string]interface{}); ok {
				bindRaw, ok := item["bind"].([]interface{})
				if ok {
					bind = bindRaw
				}
			}
		}

		output = append(output, map[string]interface{}{
			"server":                             server,
			"base_dn":                            baseDn,
			"encrypted":                          connEncrypted,
			"certificate_validation_uri":         certValidationUri,
			"download_certificate_automatically": autoDownloadCert,
			"bind":                               bind,
		})
	}

	return output
}

func expandStorageCacheDirectoryLdapBind(input []interface{}) *storagecache.CacheUsernameDownloadSettingsCredentials {
	if len(input) == 0 {
		return nil
	}
	b := input[0].(map[string]interface{})
	return &storagecache.CacheUsernameDownloadSettingsCredentials{
		BindDn:       utils.String(b["dn"].(string)),
		BindPassword: utils.String(b["password"].(string)),
	}
}

type storageCacheKeyVault struct {
	keyVaultId             string
	resourceGroupName      string
	keyVaultName           string
	location               string
	purgeProtectionEnabled bool
	softDeleteEnabled      bool
}

func storageCacheRetrieveKeyVault(ctx context.Context, keyVaultsClient *client.Client, resourcesClient *resourcesClient.Client, id string) (*storageCacheKeyVault, error) {
	keyVaultKeyId, err := keyVaultParse.ParseNestedItemID(id)
	if err != nil {
		return nil, err
	}
	keyVaultID, err := keyVaultsClient.KeyVaultIDFromBaseUrl(ctx, resourcesClient, keyVaultKeyId.KeyVaultBaseUrl)
	if err != nil {
		return nil, fmt.Errorf("retrieving the Resource ID the Key Vault at URL %q: %s", keyVaultKeyId.KeyVaultBaseUrl, err)
	}
	if keyVaultID == nil {
		return nil, fmt.Errorf("Unable to determine the Resource ID for the Key Vault at URL %q", keyVaultKeyId.KeyVaultBaseUrl)
	}

	parsedKeyVaultID, err := keyVaultParse.VaultID(*keyVaultID)
	if err != nil {
		return nil, err
	}

	resp, err := keyVaultsClient.VaultsClient.Get(ctx, parsedKeyVaultID.ResourceGroup, parsedKeyVaultID.Name)
	if err != nil {
		return nil, fmt.Errorf("retrieving %s: %+v", *parsedKeyVaultID, err)
	}

	purgeProtectionEnabled := false
	softDeleteEnabled := false

	if props := resp.Properties; props != nil {
		if props.EnableSoftDelete != nil {
			softDeleteEnabled = *props.EnableSoftDelete
		}

		if props.EnablePurgeProtection != nil {
			purgeProtectionEnabled = *props.EnablePurgeProtection
		}
	}

	location := ""
	if resp.Location != nil {
		location = *resp.Location
	}

	return &storageCacheKeyVault{
		keyVaultId:             *keyVaultID,
		resourceGroupName:      parsedKeyVaultID.ResourceGroup,
		keyVaultName:           parsedKeyVaultID.Name,
		location:               location,
		purgeProtectionEnabled: purgeProtectionEnabled,
		softDeleteEnabled:      softDeleteEnabled,
	}, nil
}

func resourceHPCCacheSchema() map[string]*pluginsdk.Schema {
	return map[string]*pluginsdk.Schema{
		"name": {
			Type:         pluginsdk.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.StringIsNotEmpty,
		},

		"resource_group_name": commonschema.ResourceGroupName(),

		"location": commonschema.Location(),

		"cache_size_in_gb": {
			Type:     pluginsdk.TypeInt,
			Required: true,
			ForceNew: true,
			ValidateFunc: validation.IntInSlice([]int{
				3072,
				6144,
				12288,
				21623,
				24576,
				43246,
				49152,
				86491,
			}),
		},

		"subnet_id": {
			Type:         pluginsdk.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validate.SubnetID,
		},

		"sku_name": {
			Type:     pluginsdk.TypeString,
			Required: true,
			ForceNew: true,
			ValidateFunc: validation.StringInSlice([]string{
				"Standard_2G",
				"Standard_4G",
				"Standard_8G",
				"Standard_L4_5G",
				"Standard_L9G",
				"Standard_L16G",
			}, false),
		},

		"mtu": {
			Type:         pluginsdk.TypeInt,
			Optional:     true,
			Default:      1500,
			ValidateFunc: validation.IntBetween(576, 1500),
		},

		"ntp_server": {
			Type:         pluginsdk.TypeString,
			Optional:     true,
			Default:      "time.windows.com",
			ValidateFunc: validation.StringIsNotEmpty,
		},

		"dns": {
			Type:     pluginsdk.TypeList,
			Optional: true,
			MaxItems: 1,
			Elem: &pluginsdk.Resource{
				Schema: map[string]*pluginsdk.Schema{
					"servers": {
						Type:     pluginsdk.TypeList,
						Required: true,
						MaxItems: 3,
						Elem: &pluginsdk.Schema{
							Type:         pluginsdk.TypeString,
							ValidateFunc: validation.IsIPAddress,
						},
					},

					"search_domain": {
						Type:         pluginsdk.TypeString,
						Optional:     true,
						ValidateFunc: validation.StringIsNotEmpty,
					},
				},
			},
		},

		"directory_active_directory": {
			Type:     pluginsdk.TypeList,
			MaxItems: 1,
			Optional: true,
			Elem: &pluginsdk.Resource{
				Schema: map[string]*pluginsdk.Schema{
					"dns_primary_ip": {
						Type:         pluginsdk.TypeString,
						Required:     true,
						ValidateFunc: validation.IsIPAddress,
					},
					"domain_name": {
						Type:         pluginsdk.TypeString,
						Required:     true,
						ValidateFunc: validation.StringIsNotEmpty,
					},
					"cache_netbios_name": {
						Type:         pluginsdk.TypeString,
						Required:     true,
						ValidateFunc: validation.StringMatch(regexp.MustCompile(`^[-0-9a-zA-Z]{1,15}$`), ""),
					},
					"domain_netbios_name": {
						Type:         pluginsdk.TypeString,
						Required:     true,
						ValidateFunc: validation.StringMatch(regexp.MustCompile(`^[-0-9a-zA-Z]{1,15}$`), ""),
					},
					"username": {
						Type:         pluginsdk.TypeString,
						Required:     true,
						ValidateFunc: validation.StringIsNotEmpty,
					},
					"password": {
						Type:         pluginsdk.TypeString,
						Required:     true,
						Sensitive:    true,
						ValidateFunc: validation.StringIsNotEmpty,
					},
					"dns_secondary_ip": {
						Type:         pluginsdk.TypeString,
						Optional:     true,
						ValidateFunc: validation.IsIPAddress,
					},
				},
			},
			ConflictsWith: []string{"directory_flat_file", "directory_ldap"},
		},

		"directory_flat_file": {
			Type:     pluginsdk.TypeList,
			MaxItems: 1,
			Optional: true,
			Elem: &pluginsdk.Resource{
				Schema: map[string]*pluginsdk.Schema{
					"group_file_uri": {
						Type:         pluginsdk.TypeString,
						Required:     true,
						ValidateFunc: validation.StringIsNotEmpty,
					},
					"password_file_uri": {
						Type:         pluginsdk.TypeString,
						Required:     true,
						ValidateFunc: validation.StringIsNotEmpty,
					},
				},
			},
			ConflictsWith: []string{"directory_active_directory", "directory_ldap"},
		},

		"directory_ldap": {
			Type:     pluginsdk.TypeList,
			MaxItems: 1,
			Optional: true,
			Elem: &pluginsdk.Resource{
				Schema: map[string]*pluginsdk.Schema{
					"server": {
						Type:         pluginsdk.TypeString,
						Required:     true,
						ValidateFunc: validation.StringIsNotEmpty,
					},

					"base_dn": {
						Type:         pluginsdk.TypeString,
						Required:     true,
						ValidateFunc: validation.StringIsNotEmpty,
					},

					"encrypted": {
						Type:     pluginsdk.TypeBool,
						Optional: true,
					},

					"certificate_validation_uri": {
						Type:         pluginsdk.TypeString,
						Optional:     true,
						ValidateFunc: validation.StringIsNotEmpty,
					},

					"download_certificate_automatically": {
						Type:         pluginsdk.TypeBool,
						Optional:     true,
						RequiredWith: []string{"directory_ldap.0.certificate_validation_uri"},
					},

					"bind": {
						Type:     pluginsdk.TypeList,
						MaxItems: 1,
						Optional: true,
						Computed: true,
						Elem: &pluginsdk.Resource{
							Schema: map[string]*pluginsdk.Schema{
								"dn": {
									Type:         pluginsdk.TypeString,
									Required:     true,
									ValidateFunc: validation.StringIsNotEmpty,
								},
								"password": {
									Type:         pluginsdk.TypeString,
									Sensitive:    true,
									Required:     true,
									ValidateFunc: validation.StringIsNotEmpty,
								},
							},
						},
					},
				},
			},
			ConflictsWith: []string{"directory_active_directory", "directory_flat_file"},
		},

		"default_access_policy": {
			Type:     pluginsdk.TypeList,
			MinItems: 1,
			MaxItems: 1,
			Optional: true,
			// This is computed because there is always a "default" policy in the cache. It is created together with the cache, and users can't remove it.
			Computed: true,
			Elem: &pluginsdk.Resource{
				Schema: map[string]*pluginsdk.Schema{
					"access_rule": {
						Type:     pluginsdk.TypeSet,
						Required: true,
						MinItems: 1,
						MaxItems: 3,
						Elem: &pluginsdk.Resource{
							Schema: map[string]*pluginsdk.Schema{
								"scope": {
									Type:     pluginsdk.TypeString,
									Required: true,
									ValidateFunc: validation.StringInSlice([]string{
										string(storagecache.NfsAccessRuleScopeDefault),
										string(storagecache.NfsAccessRuleScopeNetwork),
										string(storagecache.NfsAccessRuleScopeHost),
									}, false),
								},

								"access": {
									Type:     pluginsdk.TypeString,
									Required: true,
									ValidateFunc: validation.StringInSlice([]string{
										string(storagecache.NfsAccessRuleAccessRw),
										string(storagecache.NfsAccessRuleAccessRo),
										string(storagecache.NfsAccessRuleAccessNo),
									}, false),
								},

								"filter": {
									Type:         pluginsdk.TypeString,
									Optional:     true,
									ValidateFunc: validation.StringIsNotEmpty,
								},

								"suid_enabled": {
									Type:     pluginsdk.TypeBool,
									Optional: true,
								},

								"submount_access_enabled": {
									Type:     pluginsdk.TypeBool,
									Optional: true,
								},

								"root_squash_enabled": {
									Type:     pluginsdk.TypeBool,
									Optional: true,
								},

								"anonymous_uid": {
									Type:         pluginsdk.TypeInt,
									Optional:     true,
									ValidateFunc: validation.IntAtLeast(0),
								},

								"anonymous_gid": {
									Type:         pluginsdk.TypeInt,
									Optional:     true,
									ValidateFunc: validation.IntAtLeast(0),
								},
							},
						},
					},
				},
			},
		},

		"mount_addresses": {
			Type:     pluginsdk.TypeList,
			Computed: true,
			Elem:     &pluginsdk.Schema{Type: pluginsdk.TypeString},
		},

		"identity": commonschema.UserAssignedIdentityOptionalForceNew(),

		"key_vault_key_id": {
			Type:         pluginsdk.TypeString,
			Optional:     true,
			ValidateFunc: keyVaultValidate.NestedItemId,
			RequiredWith: []string{"identity"},
		},

		"automatically_rotate_key_to_latest_enabled": {
			Type:         pluginsdk.TypeBool,
			Optional:     true,
			RequiredWith: []string{"key_vault_key_id"},
		},

		"tags": commonschema.Tags(),
	}
}
