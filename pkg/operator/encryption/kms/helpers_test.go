package kms

import (
	"errors"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	corev1 "k8s.io/api/core/v1"

	"github.com/stretchr/testify/require"
)

func TestKeyIDFromPluginConfigSecretDataKey(t *testing.T) {
	tests := []struct {
		name      string
		dataKey   string
		wantKeyID string
		wantFound bool
		wantError bool
	}{
		{
			name:      "valid key",
			dataKey:   "kms-plugin-config-1",
			wantKeyID: "1",
			wantFound: true,
		},
		{
			name:      "valid key with large ID",
			dataKey:   "kms-plugin-config-42",
			wantKeyID: "42",
			wantFound: true,
		},
		{
			name:    "encryption-config key",
			dataKey: "encryption-config",
		},
		{
			name:      "non-integer keyID",
			dataKey:   "kms-plugin-config-abc",
			wantError: true,
		},
		{
			name:    "missing keyID",
			dataKey: "kms-plugin-config-",
		},
		{
			name:    "empty string",
			dataKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, found, err := KeyIDFromPluginConfigSecretDataKey(tt.dataKey)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantFound, found)
			if found {
				require.Equal(t, tt.wantKeyID, keyID)
			}
		})
	}
}

func TestToPluginConfigSecretDataKeyFor(t *testing.T) {
	tests := []struct {
		name      string
		keyID     string
		wantKey   string
		wantError bool
	}{
		{
			name:    "valid keyID",
			keyID:   "1",
			wantKey: "kms-plugin-config-1",
		},
		{
			name:    "valid large keyID",
			keyID:   "42",
			wantKey: "kms-plugin-config-42",
		},
		{
			name:      "non-integer keyID",
			keyID:     "abc",
			wantError: true,
		},
		{
			name:      "empty keyID",
			keyID:     "",
			wantError: true,
		},
		{
			name:      "negative keyID",
			keyID:     "-1",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToPluginConfigSecretDataKeyFor(tt.keyID)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantKey, got)
		})
	}
}

func TestAddKMSPluginVolume(t *testing.T) {
	directoryOrCreate := corev1.HostPathDirectoryOrCreate

	tests := []struct {
		name                string
		featureGateAccessor featuregates.FeatureGateAccess
		actualPodSpec       *corev1.PodSpec
		expectedPodSpec     *corev1.PodSpec
		containerName       string
		expectError         bool
	}{
		{
			name: "nil pod: returns error",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{features.FeatureGateKMSEncryption},
				[]configv1.FeatureGateName{},
			),
			actualPodSpec:   nil,
			expectedPodSpec: nil,
			containerName:   "kube-apiserver",
			expectError:     true,
		},
		{
			name: "container not found: returns error",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{features.FeatureGateKMSEncryption},
				[]configv1.FeatureGateName{},
			),
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "other-container"},
				},
			},
			expectedPodSpec: nil,
			containerName:   "kube-apiserver",
			expectError:     true,
		},
		{
			name: "feature gates not observed: no volume added",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccessForTesting(
				nil,
				nil,
				make(chan struct{}),
				nil,
			),
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
			},
			containerName: "kube-apiserver",
			expectError:   false,
		},
		{
			name: "feature gate accessor error: returns error",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccessForTesting(
				nil,
				nil,
				func() chan struct{} { ch := make(chan struct{}); close(ch); return ch }(),
				errors.New("some error"),
			),
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
			},
			expectedPodSpec: nil,
			containerName:   "kube-apiserver",
			expectError:     true,
		},
		{
			name: "KMSEncryption feature gate disabled: no volume added",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{},
				[]configv1.FeatureGateName{features.FeatureGateKMSEncryption},
			),
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
			},
			containerName: "kube-apiserver",
			expectError:   false,
		},
		{
			name: "KMSEncryption feature gate enabled: volume and mount added",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{features.FeatureGateKMSEncryption},
				[]configv1.FeatureGateName{},
			),
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "kube-apiserver"},
				},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{
							{Name: "kms-plugin-socket", MountPath: "/var/run/kmsplugin"},
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "kms-plugin-socket",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/run/kmsplugin",
								Type: &directoryOrCreate,
							},
						},
					},
				},
			},
			containerName: "kube-apiserver",
			expectError:   false,
		},
		{
			name: "KMSEncryption feature gate enabled: only kube-apiserver container gets mount",
			featureGateAccessor: featuregates.NewHardcodedFeatureGateAccess(
				[]configv1.FeatureGateName{features.FeatureGateKMSEncryption},
				[]configv1.FeatureGateName{},
			),
			actualPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "other-container"},
					{Name: "kube-apiserver"},
					{Name: "another-container"},
				},
			},
			expectedPodSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "other-container"},
					{
						Name: "kube-apiserver",
						VolumeMounts: []corev1.VolumeMount{
							{Name: "kms-plugin-socket", MountPath: "/var/run/kmsplugin"},
						},
					},
					{Name: "another-container"},
				},
				Volumes: []corev1.Volume{
					{
						Name: "kms-plugin-socket",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/run/kmsplugin",
								Type: &directoryOrCreate,
							},
						},
					},
				},
			},
			containerName: "kube-apiserver",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AddKMSPluginVolumeAndMountToPodSpec(tt.actualPodSpec, tt.containerName, tt.featureGateAccessor)

			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedPodSpec, tt.actualPodSpec)
		})
	}
}
