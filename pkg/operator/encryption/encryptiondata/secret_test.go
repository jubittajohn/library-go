package encryptiondata_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
)

func TestExtractUniqueAndSortedKMSConfigurations(t *testing.T) {
	timeout := &metav1.Duration{Duration: 10 * time.Second}

	tests := []struct {
		name      string
		cfg       *encryptiondata.Config
		want      []*apiserverconfigv1.KMSConfiguration
		wantError bool
	}{
		{
			name:      "nil encryption returns error",
			cfg:       nil,
			wantError: true,
		},
		{
			name:      "nil encryption returns error",
			cfg:       &encryptiondata.Config{},
			wantError: true,
		},
		{
			name: "empty provider list returns empty slice",
			cfg: &encryptiondata.Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{{
						Resources: []string{"secrets"},
						Providers: []apiserverconfigv1.ProviderConfiguration{},
					}},
				},
			},
			want: []*apiserverconfigv1.KMSConfiguration{},
		},
		{
			name: "single resource single KMS provider",
			cfg: &encryptiondata.Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{{
						Resources: []string{"secrets"},
						Providers: []apiserverconfigv1.ProviderConfiguration{{
							KMS: &apiserverconfigv1.KMSConfiguration{
								APIVersion: "v2",
								Name:       "1_secrets",
								Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
								Timeout:    timeout,
							},
						}},
					}},
				},
			},
			want: []*apiserverconfigv1.KMSConfiguration{{
				APIVersion: "v2",
				Name:       "1",
				Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
				Timeout:    timeout,
			}},
		},
		{
			name: "same keyID across resources is deduplicated",
			cfg: &encryptiondata.Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{
						{
							Resources: []string{"secrets"},
							Providers: []apiserverconfigv1.ProviderConfiguration{{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "1_secrets",
									Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
									Timeout:    timeout,
								},
							}},
						},
						{
							Resources: []string{"configmaps"},
							Providers: []apiserverconfigv1.ProviderConfiguration{{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "1_configmaps",
									Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
									Timeout:    timeout,
								},
							}},
						},
					},
				},
			},
			want: []*apiserverconfigv1.KMSConfiguration{{
				APIVersion: "v2",
				Name:       "1",
				Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
				Timeout:    timeout,
			}},
		},
		{
			name: "multiple keyIDs sorted descending",
			cfg: &encryptiondata.Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{{
						Resources: []string{"secrets"},
						Providers: []apiserverconfigv1.ProviderConfiguration{
							{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "1_secrets",
									Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
									Timeout:    timeout,
								},
							},
							{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "3_secrets",
									Endpoint:   "unix:///var/run/kmsplugin/kms-3.sock",
									Timeout:    timeout,
								},
							},
							{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "2_secrets",
									Endpoint:   "unix:///var/run/kmsplugin/kms-2.sock",
									Timeout:    timeout,
								},
							},
						},
					}},
				},
			},
			want: []*apiserverconfigv1.KMSConfiguration{
				{APIVersion: "v2", Name: "3", Endpoint: "unix:///var/run/kmsplugin/kms-3.sock", Timeout: timeout},
				{APIVersion: "v2", Name: "2", Endpoint: "unix:///var/run/kmsplugin/kms-2.sock", Timeout: timeout},
				{APIVersion: "v2", Name: "1", Endpoint: "unix:///var/run/kmsplugin/kms-1.sock", Timeout: timeout},
			},
		},
		{
			name: "non-KMS providers are skipped",
			cfg: &encryptiondata.Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{{
						Resources: []string{"secrets"},
						Providers: []apiserverconfigv1.ProviderConfiguration{
							{Identity: &apiserverconfigv1.IdentityConfiguration{}},
							{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "1_secrets",
									Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
									Timeout:    timeout,
								},
							},
							{AESCBC: &apiserverconfigv1.AESConfiguration{Keys: []apiserverconfigv1.Key{{Name: "k", Secret: "s"}}}},
						},
					}},
				},
			},
			want: []*apiserverconfigv1.KMSConfiguration{{
				APIVersion: "v2",
				Name:       "1",
				Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
				Timeout:    timeout,
			}},
		},
		{
			name: "mismatched duplicate keyID errors",
			cfg: &encryptiondata.Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{
						{
							Resources: []string{"secrets"},
							Providers: []apiserverconfigv1.ProviderConfiguration{{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "1_secrets",
									Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
									Timeout:    timeout,
								},
							}},
						},
						{
							Resources: []string{"configmaps"},
							Providers: []apiserverconfigv1.ProviderConfiguration{{
								KMS: &apiserverconfigv1.KMSConfiguration{
									APIVersion: "v2",
									Name:       "1_configmaps",
									Endpoint:   "unix:///var/run/kmsplugin/kms-DIFFERENT.sock",
									Timeout:    timeout,
								},
							}},
						},
					},
				},
			},
			wantError: true,
		},
		{
			name: "invalid plugin name errors",
			cfg: &encryptiondata.Config{
				Encryption: &apiserverconfigv1.EncryptionConfiguration{
					Resources: []apiserverconfigv1.ResourceConfiguration{{
						Resources: []string{"secrets"},
						Providers: []apiserverconfigv1.ProviderConfiguration{{
							KMS: &apiserverconfigv1.KMSConfiguration{
								APIVersion: "v2",
								Name:       "no-underscore",
								Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
							},
						}},
					}},
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptiondata.ExtractUniqueAndSortedKMSConfigurations(tt.cfg)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
