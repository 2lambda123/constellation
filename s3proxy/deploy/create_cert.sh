#!/usr/bin/env bash
# service is the name of the s3proxy service in kubernetes.
# It does not have to match the actual running service, though it may help for consistency.
service=s3proxy

# namespace where the s3proxy service is running.
namespace=default

# secret_name to create in the kubernetes secrets store.
secret_name=s3proxy-tls

# tmpdir is a temporary working directory.
tmpdir=$(mktemp -d)

# csr_name will be the name of our certificate signing request as seen by kubernetes.
csr_name=s3proxy-csr

openssl genrsa -out "$tmpdir"/s3proxy.key 2048

cat << EOF > "$tmpdir"/csr.conf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = *.${service}
DNS.2 = *.${service}.${namespace}
DNS.3 = *.${service}.${namespace}.svc
DNS.4 = *.${service}.${namespace}.svc.cluster.local
DNS.5 = *.${service}-internal
DNS.6 = *.${service}-internal.${namespace}
DNS.7 = *.${service}-internal.${namespace}.svc
DNS.8 = *.${service}-internal.${namespace}.svc.cluster.local
DNS.9 = s3.eu-west-1.amazonaws.com
IP.1 = 127.0.0.1
EOF

openssl req -new -key "$tmpdir"/s3proxy.key \
  -subj "/O=system:nodes/CN=system:node:${service}.${namespace}.svc" \
  -out "$tmpdir"/server.csr \
  -config "$tmpdir"/csr.conf

cat << EOF > "$tmpdir"/csr.yaml
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ${csr_name}
spec:
  groups:
  - system:authenticated
  request: $(cat "$tmpdir"/server.csr | base64 | tr -d '\r\n')
  signerName: kubernetes.io/kubelet-serving
  usages:
  - digital signature
  - key encipherment
  - server auth
EOF

kubectl create -f "$tmpdir"/csr.yaml --dry-run=client -o yaml --save-config | kubectl apply -f -
kubectl certificate approve "$csr_name"
kubectl get csr "$csr_name"

serverCert=$(kubectl get csr "$csr_name" -o jsonpath='{.status.certificate}')
echo "$serverCert" | openssl base64 -d -A -out "$tmpdir"/s3proxy.crt
kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[].cluster.certificate-authority-data}' | base64 -d > "$tmpdir"/s3proxy.ca
kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic "$secret_name" \
  --namespace "$namespace" \
  --from-file=s3proxy.key="$tmpdir"/s3proxy.key \
  --from-file=s3proxy.crt="$tmpdir"/s3proxy.crt \
  --from-file=s3proxy.ca="$tmpdir"/s3proxy.ca --dry-run=client -o yaml --save-config | kubectl apply -f -

rm -rf "$tmpdir"
