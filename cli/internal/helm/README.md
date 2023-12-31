# Helm

Constellation uses [helm](https://helm.sh/) to install and upgrade deployments to the Kubernetes cluster.
Helm wraps deployments into charts. One chart should contain all the configuration needed to run a deployment.

## Charts used by Constellation

To make installation and lifecycle management easier, Constellation groups multiple related charts into sub-charts.
The following "parent" charts are used by Constellation:

* [cert-manager](./charts/cert-manager/)

* [Cilium](./charts/cilium/)

* [constellation-services](./charts/edgeless/constellation-services/)

    Cluster services (mostly) written by us, providing basic functionality of the cluster

* [csi](./charts/edgeless/csi/)

    Our modified Kubernetes CSI drivers and Snapshot controller/CRDs

* [operators](./charts/edgeless/operators/)

    Kubernetes operators we use to control and manage the lifecycle of a Constellation cluster

## Chart upgrades

All services that are installed via helm-install are upgraded via helm-upgrade.
Two aspects are not full covered by running helm-upgrade: CRDs and values.
While helm-install can install CRDs if they are contained in a chart's `crds` folder, upgrade won't change any installed CRDs.
Furthermore, new values introduced with a new version of a chart will not be installed into the cluster if the `--reuse-values` flag is set.
Nevertheless, we have to rely on the values already present in the cluster because some of the values are set by the bootstrapper during installation.
Because upgrades should be a CLI-only operation and we want to avoid the behaviour of `--reuse-values`, we fetch the cluster values and merge them with any new values.

Here is how we manage CRD upgrades for each chart.

### Cilium

* CRDs are updated by cilium-operator.

### cert-manager

* installCRDs flag is set during upgrade. This flag is managed by cert-manager. cert-manager is in charge of correctly upgrading the CRDs.
* WARNING: upgrading cert-manager might break other installations of cert-manager in the cluster, if those other installation are not on the same version as the Constellation-manager installation. This is due to the cluster-wide CRDs.

### Operators

* Manually update CRDs before upgrading the chart. Update by applying the CRDs found in the `operators/crds/` folder.

### Constellation-services

* There currently are no CRDs in this chart.

### CSI

* CRDs are required for enabling snapshot support
* CRDs are provided as their own helm chart and may be updated using helm
