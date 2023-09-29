/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package router

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/edgelesssys/constellation/v2/s3proxy/internal/crypto"
)

const (
	// testingKey is a temporary encryption key used for testing.
	// TODO (derpsteb): This key needs to be fetched from Constellation's keyservice.
	testingKey = "01234567890123456789012345678901"
	// encryptionTag is the key used to tag objects that are encrypted with this proxy. Presence of the key implies the object needs to be decrypted.
	encryptionTag = "constellation-encryption"
)

// object bundles data to implement http.Handler methods that use data from incoming requests.
type object struct {
	client                    s3Client
	key                       string
	bucket                    string
	data                      []byte
	query                     url.Values
	tags                      string
	contentType               string
	metadata                  map[string]string
	objectLockLegalHoldStatus string
	objectLockMode            string
	objectLockRetainUntilDate time.Time
	log                       *slog.Logger
}

// TODO(derpsteb): serve all headers present in s3.GetObjectOutput in s3 proxy response. currently we only serve those required to make minio/mint pass.
func (o object) get(w http.ResponseWriter, r *http.Request) {
	o.log.Debug("getObject", "key", o.key, "host", o.bucket)

	versionID, ok := o.query["versionId"]
	if !ok {
		versionID = []string{""}
	}

	data, err := o.client.GetObject(r.Context(), o.bucket, o.key, versionID[0])
	if err != nil {
		// log with Info as it might be expected behavior (e.g. object not found).
		o.log.Error("GetObject sending request to S3", "error", err)

		// We want to forward error codes from the s3 API to clients as much as possible.
		code := parseErrorCode(err)
		if code != 0 {
			http.Error(w, err.Error(), code)
			return
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if data.ETag != nil {
		w.Header().Set("ETag", strings.Trim(*data.ETag, "\""))
	}

	body, err := io.ReadAll(data.Body)
	if err != nil {
		o.log.Error("GetObject reading S3 response", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	plaintext := body
	decrypt, ok := data.Metadata[encryptionTag]

	if ok && decrypt == "true" {
		plaintext, err = crypto.Decrypt(body, []byte(testingKey))
		if err != nil {
			o.log.Error("GetObject decrypting response", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(plaintext); err != nil {
		o.log.Error("GetObject sending response", "error", err)
	}
}

func (o object) put(w http.ResponseWriter, r *http.Request) {
	ciphertext, err := crypto.Encrypt(o.data, []byte(testingKey))
	if err != nil {
		o.log.Error("PutObject", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// We need to tag objects that are encrypted with this proxy,
	// because there might be objects in a bucket that are not encrypted.
	// GetObject needs to be able to recognize these objects and skip decryption.
	o.metadata[encryptionTag] = "true"

	output, err := o.client.PutObject(r.Context(), o.bucket, o.key, o.tags, o.contentType, o.objectLockLegalHoldStatus, o.objectLockMode, o.objectLockRetainUntilDate, o.metadata, ciphertext)
	if err != nil {
		o.log.Error("PutObject sending request to S3", "error", err)

		// We want to forward error codes from the s3 API to clients whenever possible.
		code := parseErrorCode(err)
		if code != 0 {
			http.Error(w, err.Error(), code)
			return
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("x-amz-server-side-encryption", string(output.ServerSideEncryption))

	if output.VersionId != nil {
		w.Header().Set("x-amz-version-id", *output.VersionId)
	}
	if output.ETag != nil {
		w.Header().Set("ETag", *output.ETag)
	}
	if output.Expiration != nil {
		w.Header().Set("x-amz-expiration", *output.Expiration)
	}
	if output.ChecksumCRC32 != nil {
		w.Header().Set("x-amz-checksum-crc32", *output.ChecksumCRC32)
	}
	if output.ChecksumCRC32C != nil {
		w.Header().Set("x-amz-checksum-crc32c", *output.ChecksumCRC32C)
	}
	if output.ChecksumSHA1 != nil {
		w.Header().Set("x-amz-checksum-sha1", *output.ChecksumSHA1)
	}
	if output.ChecksumSHA256 != nil {
		w.Header().Set("x-amz-checksum-sha256", *output.ChecksumSHA256)
	}
	if output.SSECustomerAlgorithm != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", *output.SSECustomerAlgorithm)
	}
	if output.SSECustomerKeyMD5 != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", *output.SSECustomerKeyMD5)
	}
	if output.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *output.SSEKMSKeyId)
	}
	if output.SSEKMSEncryptionContext != nil {
		w.Header().Set("x-amz-server-side-encryption-context", *output.SSEKMSEncryptionContext)
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(nil); err != nil {
		o.log.Error("PutObject sending response", "error", err)
	}
}

func parseErrorCode(err error) int {
	regex := regexp.MustCompile(`https response error StatusCode: (\d+)`)
	matches := regex.FindStringSubmatch(err.Error())
	if len(matches) > 1 {
		code, _ := strconv.Atoi(matches[1])
		return code
	}

	return 0
}

type s3Client interface {
	GetObject(ctx context.Context, bucket, key, versionID string) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, bucket, key, tags, contentType, objectLockLegalHoldStatus, objectLockMode string, objectLockRetainUntilDate time.Time, metadata map[string]string, body []byte) (*s3.PutObjectOutput, error)
}
