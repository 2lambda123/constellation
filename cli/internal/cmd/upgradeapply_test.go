/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package cmd

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/edgelesssys/constellation/v2/cli/internal/clusterid"
	"github.com/edgelesssys/constellation/v2/cli/internal/helm"
	"github.com/edgelesssys/constellation/v2/cli/internal/kubecmd"
	"github.com/edgelesssys/constellation/v2/cli/internal/terraform"
	"github.com/edgelesssys/constellation/v2/internal/attestation/variant"
	"github.com/edgelesssys/constellation/v2/internal/cloud/cloudprovider"
	"github.com/edgelesssys/constellation/v2/internal/config"
	"github.com/edgelesssys/constellation/v2/internal/constants"
	"github.com/edgelesssys/constellation/v2/internal/file"
	"github.com/edgelesssys/constellation/v2/internal/kms/uri"
	"github.com/edgelesssys/constellation/v2/internal/logger"
	"github.com/edgelesssys/constellation/v2/internal/versions"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestUpgradeApply(t *testing.T) {
	testCases := map[string]struct {
		helmUpgrader      helmApplier
		kubeUpgrader      *stubKubernetesUpgrader
		terraformUpgrader clusterUpgrader
		wantErr           bool
		flags             upgradeApplyFlags
		stdin             string
	}{
		"success": {
			kubeUpgrader:      &stubKubernetesUpgrader{currentConfig: config.DefaultForAzureSEVSNP()},
			helmUpgrader:      stubApplier{},
			terraformUpgrader: &stubTerraformUpgrader{},
			flags:             upgradeApplyFlags{yes: true},
		},
		"nodeVersion some error": {
			kubeUpgrader: &stubKubernetesUpgrader{
				currentConfig:  config.DefaultForAzureSEVSNP(),
				nodeVersionErr: assert.AnError,
			},
			helmUpgrader:      stubApplier{},
			terraformUpgrader: &stubTerraformUpgrader{},
			wantErr:           true,
			flags:             upgradeApplyFlags{yes: true},
		},
		"nodeVersion in progress error": {
			kubeUpgrader: &stubKubernetesUpgrader{
				currentConfig:  config.DefaultForAzureSEVSNP(),
				nodeVersionErr: kubecmd.ErrInProgress,
			},
			helmUpgrader:      stubApplier{},
			terraformUpgrader: &stubTerraformUpgrader{},
			flags:             upgradeApplyFlags{yes: true},
		},
		"helm other error": {
			kubeUpgrader: &stubKubernetesUpgrader{
				currentConfig: config.DefaultForAzureSEVSNP(),
			},
			helmUpgrader:      stubApplier{err: assert.AnError},
			terraformUpgrader: &stubTerraformUpgrader{},
			wantErr:           true,
			flags:             upgradeApplyFlags{yes: true},
		},
		"abort": {
			kubeUpgrader: &stubKubernetesUpgrader{
				currentConfig: config.DefaultForAzureSEVSNP(),
			},
			helmUpgrader:      stubApplier{},
			terraformUpgrader: &stubTerraformUpgrader{terraformDiff: true},
			wantErr:           true,
			stdin:             "no\n",
		},
		"plan terraform error": {
			kubeUpgrader: &stubKubernetesUpgrader{
				currentConfig: config.DefaultForAzureSEVSNP(),
			},
			helmUpgrader:      stubApplier{},
			terraformUpgrader: &stubTerraformUpgrader{planTerraformErr: assert.AnError},
			wantErr:           true,
			flags:             upgradeApplyFlags{yes: true},
		},
		"apply terraform error": {
			kubeUpgrader: &stubKubernetesUpgrader{
				currentConfig: config.DefaultForAzureSEVSNP(),
			},
			helmUpgrader: stubApplier{},
			terraformUpgrader: &stubTerraformUpgrader{
				applyTerraformErr: assert.AnError,
				terraformDiff:     true,
			},
			wantErr: true,
			flags:   upgradeApplyFlags{yes: true},
		},
		"skip all upgrade phases": {
			kubeUpgrader: &stubKubernetesUpgrader{
				currentConfig: config.DefaultForAzureSEVSNP(),
			},
			helmUpgrader:      &mockApplier{}, // mocks ensure that no methods are called
			terraformUpgrader: &mockTerraformUpgrader{},
			flags: upgradeApplyFlags{
				skipPhases: []skipPhase{skipInfrastructurePhase, skipHelmPhase, skipK8sPhase, skipImagePhase},
				yes:        true,
			},
		},
		"skip all phases except node upgrade": {
			kubeUpgrader: &stubKubernetesUpgrader{
				currentConfig: config.DefaultForAzureSEVSNP(),
			},
			helmUpgrader:      &mockApplier{}, // mocks ensure that no methods are called
			terraformUpgrader: &mockTerraformUpgrader{},
			flags: upgradeApplyFlags{
				skipPhases: []skipPhase{skipInfrastructurePhase, skipHelmPhase, skipK8sPhase},
				yes:        true,
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			cmd := newUpgradeApplyCmd()
			cmd.SetIn(bytes.NewBufferString(tc.stdin))

			handler := file.NewHandler(afero.NewMemMapFs())

			cfg := defaultConfigWithExpectedMeasurements(t, config.Default(), cloudprovider.Azure)

			require.NoError(handler.WriteYAML(constants.ConfigFilename, cfg))
			require.NoError(handler.WriteJSON(constants.ClusterIDsFilename, clusterid.File{MeasurementSalt: []byte("measurementSalt")}))
			require.NoError(handler.WriteJSON(constants.MasterSecretFilename, uri.MasterSecret{}))

			upgrader := upgradeApplyCmd{
				kubeUpgrader:    tc.kubeUpgrader,
				helmApplier:     tc.helmUpgrader,
				clusterUpgrader: tc.terraformUpgrader,
				log:             logger.NewTest(t),
				configFetcher:   stubAttestationFetcher{},
				clusterShower:   &stubShowCluster{},
				fileHandler:     handler,
			}

			err := upgrader.upgradeApply(cmd, "test", tc.flags)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Equal(!tc.flags.skipPhases.contains(skipImagePhase), tc.kubeUpgrader.calledNodeUpgrade,
				"incorrect node upgrade skipping behavior")
		})
	}
}

func TestUpgradeApplyFlagsForSkipPhases(t *testing.T) {
	cmd := newUpgradeApplyCmd()
	cmd.Flags().String("workspace", "", "")  // register persistent flag manually
	cmd.Flags().Bool("force", true, "")      // register persistent flag manually
	cmd.Flags().String("tf-log", "NONE", "") // register persistent flag manually
	require.NoError(t, cmd.Flags().Set("skip-phases", "infrastructure,helm,k8s,image"))
	result, err := parseUpgradeApplyFlags(cmd)
	if err != nil {
		t.Fatalf("Error while parsing flags: %v", err)
	}
	assert.ElementsMatch(t, []skipPhase{skipInfrastructurePhase, skipHelmPhase, skipK8sPhase, skipImagePhase}, result.skipPhases)
}

type stubKubernetesUpgrader struct {
	nodeVersionErr    error
	k8sErr            error
	currentConfig     config.AttestationCfg
	calledNodeUpgrade bool
}

func (u *stubKubernetesUpgrader) BackupCRDs(_ context.Context, _ string) ([]apiextensionsv1.CustomResourceDefinition, error) {
	return []apiextensionsv1.CustomResourceDefinition{}, nil
}

func (u *stubKubernetesUpgrader) BackupCRs(_ context.Context, _ []apiextensionsv1.CustomResourceDefinition, _ string) error {
	return nil
}

func (u *stubKubernetesUpgrader) UpgradeImageVersion(_ context.Context, _ *config.Config, _ bool) error {
	u.calledNodeUpgrade = true
	return u.nodeVersionErr
}

func (u *stubKubernetesUpgrader) UpgradeK8sVersion(_ context.Context, _ versions.ValidK8sVersion, _ bool) error {
	return u.k8sErr
}

func (u *stubKubernetesUpgrader) ApplyJoinConfig(_ context.Context, _ config.AttestationCfg, _ []byte) error {
	return nil
}

func (u *stubKubernetesUpgrader) GetClusterAttestationConfig(_ context.Context, _ variant.Variant) (config.AttestationCfg, error) {
	return u.currentConfig, nil
}

func (u *stubKubernetesUpgrader) ExtendClusterConfigCertSANs(_ context.Context, _ []string) error {
	return nil
}

// TODO(v2.11): Remove this function after v2.11 is released.
func (u *stubKubernetesUpgrader) RemoveAttestationConfigHelmManagement(_ context.Context) error {
	return nil
}

// TODO(v2.12): Remove this function.
func (u *stubKubernetesUpgrader) RemoveHelmKeepAnnotation(_ context.Context) error {
	return nil
}

type stubTerraformUpgrader struct {
	terraformDiff     bool
	planTerraformErr  error
	applyTerraformErr error
}

func (u stubTerraformUpgrader) PlanClusterUpgrade(_ context.Context, _ io.Writer, _ terraform.Variables, _ cloudprovider.Provider) (bool, error) {
	return u.terraformDiff, u.planTerraformErr
}

func (u stubTerraformUpgrader) ApplyClusterUpgrade(_ context.Context, _ cloudprovider.Provider) (terraform.ApplyOutput, error) {
	return terraform.ApplyOutput{}, u.applyTerraformErr
}

type mockTerraformUpgrader struct {
	mock.Mock
}

func (m *mockTerraformUpgrader) PlanClusterUpgrade(ctx context.Context, w io.Writer, variables terraform.Variables, provider cloudprovider.Provider) (bool, error) {
	args := m.Called(ctx, w, variables, provider)
	return args.Bool(0), args.Error(1)
}

func (m *mockTerraformUpgrader) ApplyClusterUpgrade(ctx context.Context, provider cloudprovider.Provider) (terraform.ApplyOutput, error) {
	args := m.Called(ctx, provider)
	return args.Get(0).(terraform.ApplyOutput), args.Error(1)
}

type mockApplier struct {
	mock.Mock
}

func (m *mockApplier) PrepareApply(cfg *config.Config, k8sVersion versions.ValidK8sVersion, clusterID clusterid.File, helmOpts helm.Options, terraformOut terraform.ApplyOutput, str string, masterSecret uri.MasterSecret) (helm.Applier, bool, error) {
	args := m.Called(cfg, k8sVersion, clusterID, helmOpts, terraformOut, str, masterSecret)
	return args.Get(0).(helm.Applier), args.Bool(1), args.Error(2)
}
