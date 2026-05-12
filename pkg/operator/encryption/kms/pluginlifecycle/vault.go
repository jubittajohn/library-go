package pluginlifecycle

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
)

// newVaultSidecarProvider creates a Vault sidecar provider from the given KMS plugin configuration.
func newVaultSidecarProvider(name, keyID, udsPath string, pluginConfig configv1.KMSPluginConfig) (*vault, error) {
	return &vault{
		name:    name,
		keyID:   keyID,
		udsPath: udsPath,
		config:  &pluginConfig.Vault,
	}, nil
}

// vault implements SidecarProvider for HashiCorp Vault KMS.
type vault struct {
	name    string
	keyID   string
	udsPath string
	config  *configv1.VaultKMSPluginConfig
}

// Name returns the sidecar name appended by the key id.
func (v *vault) Name() string {
	return fmt.Sprintf("%s-%s", v.name, v.keyID)
}

// BuildSidecarContainer returns a container spec for the Vault KMS plugin sidecar
// configured with the Vault address, namespace, transit mount, and transit key.
func (v *vault) BuildSidecarContainer() (corev1.Container, error) {
	return corev1.Container{
		Name:  v.Name(),
		Image: v.config.KMSPluginImage,
		Args: []string{
			// TODO(bertinatto): this path is a placeholder for the mock plugin. This path doesn't exist. It will need to be validated
			// once we support the actual Vault plugin. It'll likely be different for KASO vs. aggregated API server operators.
			fmt.Sprintf("-approle-secret-id-path=/var/run/secrets/vault-kms/secret-id-%s", v.keyID),
			fmt.Sprintf("-listen-address=%s", v.udsPath),
			fmt.Sprintf("-vault-address=%s", v.config.VaultAddress),
			fmt.Sprintf("-vault-namespace=%s", v.config.VaultNamespace),
			fmt.Sprintf("-transit-mount=%s", v.config.TransitMount),
			fmt.Sprintf("-transit-key=%s", v.config.TransitKey),
		},
	}, nil
}
