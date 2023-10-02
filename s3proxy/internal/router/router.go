/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

/*
Package router implements the main interception logic of s3proxy.
It decides which packages to forward and which to intercept.

The routing logic in this file is taken from this blog post: https://benhoyt.com/writings/go-routing/#regex-switch.
We should be able to replace this once this is part of the stdlib: https://github.com/golang/go/issues/61410.

If the router intercepts a PutObject request it will encrypt the body before forwarding it to the S3 API.
The stored object will have a tag that holds an encrypted data encryption key (DEK).
That DEK is used to encrypt the object's body.
The DEK is generated randomly for each PutObject request.
The DEK is encrypted with a key encryption key (KEK) fetched from Constellation's keyservice.
*/
package router

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/edgelesssys/constellation/v2/s3proxy/internal/kms"
	"github.com/edgelesssys/constellation/v2/s3proxy/internal/s3"
)

// Use a 32*8 = 256 bit key for AES-256.
const (
	kekSize = 32
	kekID   = "s3proxy-kek"
)

var (
	regexen = make(map[string]*regexp.Regexp)
	relock  sync.Mutex
)

// Router implements the interception logic for the s3proxy.
type Router struct {
	region string
	kek    []byte
	log    *slog.Logger
}

// New creates a new Router.
func New(region, endpoint string, log *slog.Logger) (Router, error) {
	kms := kms.New(log, endpoint)

	// Get the key encryption key that encrypts all DEKs.
	kek, err := kms.GetDataKey(context.Background(), kekID, kekSize)
	if err != nil {
		return Router{}, fmt.Errorf("getting KEK: %w", err)
	}
	if len(kek) != kekSize {
		return Router{}, fmt.Errorf("received KEK is %d bytes long, expected %d", len(kek), kekSize)
	}

	return Router{region: region, kek: kek, log: log}, nil
}

// Serve implements the routing logic for the s3 proxy.
// It intercepts GetObject and PutObject requests, encrypting/decrypting their bodies if necessary.
// All other requests are forwarded to the S3 API.
// Ideally we could separate routing logic, request handling and s3 interactions.
// Currently routing logic and request handling are integrated.
func (r Router) Serve(w http.ResponseWriter, req *http.Request) {
	var h http.Handler
	var key string
	var bucket string

	client, err := s3.NewClient(r.region)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	path := req.URL.Path
	switch {
	// intercept GetObject.
	case containsBucket(req.Host) && match(path, "/(.+)", &key) && req.Method == "GET" && !isGetObjectX(req.URL.Query()):
		// BUCKET.s3.REGION.amazonaws.com
		parts := strings.Split(req.Host, ".")
		bucket := parts[0]

		if req.Header.Get("Range") != "" {
			r.log.Error("GetObject Range header unsupported")
			http.Error(w, "s3proxy currently does not support Range headers", http.StatusNotImplemented)
		}

		obj := object{
			kek:                  r.kek,
			client:               client,
			key:                  key,
			bucket:               bucket,
			query:                req.URL.Query(),
			sseCustomerAlgorithm: req.Header.Get("x-amz-server-side-encryption-customer-algorithm"),
			sseCustomerKey:       req.Header.Get("x-amz-server-side-encryption-customer-key"),
			sseCustomerKeyMD5:    req.Header.Get("x-amz-server-side-encryption-customer-key-MD5"),
			log:                  r.log,
		}
		h = get(obj.get)
	case !containsBucket(req.Host) && match(path, "/([^/?]+)/(.+)", &bucket, &key) && req.Method == "GET" && !isGetObjectX(req.URL.Query()):
		if req.Header.Get("Range") != "" {
			r.log.Error("GetObject Range header unsupported")
			http.Error(w, "s3proxy currently does not support Range headers", http.StatusNotImplemented)
		}

		obj := object{
			kek:                  r.kek,
			client:               client,
			key:                  key,
			bucket:               bucket,
			query:                req.URL.Query(),
			sseCustomerAlgorithm: req.Header.Get("x-amz-server-side-encryption-customer-algorithm"),
			sseCustomerKey:       req.Header.Get("x-amz-server-side-encryption-customer-key"),
			sseCustomerKeyMD5:    req.Header.Get("x-amz-server-side-encryption-customer-key-MD5"),
			log:                  r.log,
		}
		h = get(obj.get)

	case containsBucket(req.Host) && match(path, "/(.+)", &key) && req.Method == "PUT" && !isUnwantedPutEndpoint(req.Header, req.URL.Query()):
		// BUCKET.s3.REGION.amazonaws.com
		parts := strings.Split(req.Host, ".")
		bucket := parts[0]

		r.log.Debug("intercepting", "path", req.URL.Path, "method", req.Method, "host", req.Host)
		body, err := io.ReadAll(req.Body)
		if err != nil {
			r.log.Error("PutObject", "error", err)
			http.Error(w, fmt.Sprintf("reading body: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		clientDigest := req.Header.Get("x-amz-content-sha256")
		serverDigest := sha256sum(body)

		// There may be a client that wants to test that incorrect content digests result in API errors.
		// For encrypting the body we have to recalculate the content digest.
		// If the client intentionally sends a mismatching content digest, we would take the client request, rewrap it,
		// calculate the correct digest for the new body and NOT get an error.
		// Thus we have to check incoming requets for matching content digests.
		// UNSIGNED-PAYLOAD can be used to disabled payload signing. In that case we don't check the content digest.
		if clientDigest != "" && clientDigest != "UNSIGNED-PAYLOAD" && clientDigest != serverDigest {
			r.log.Debug("PutObject", "error", "x-amz-content-sha256 mismatch")
			// The S3 API responds with an XML formatted error message.
			mismatchErr := NewContentSHA256MismatchError(clientDigest, serverDigest)
			marshalled, err := xml.Marshal(mismatchErr)
			if err != nil {
				r.log.Error("PutObject", "error", err)
				http.Error(w, fmt.Sprintf("marshalling error: %s", err.Error()), http.StatusInternalServerError)
				return
			}

			http.Error(w, string(marshalled), http.StatusBadRequest)
			return
		}

		metadata := getMetadataHeaders(req.Header)

		raw := req.Header.Get("x-amz-object-lock-retain-until-date")
		retentionTime, err := parseRetentionTime(raw)
		if err != nil {
			r.log.Error("parsing lock retention time", "data", raw, "error", err.Error())
			http.Error(w, fmt.Sprintf("parsing x-amz-object-lock-retain-until-date: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		err = validateContentMD5(req.Header.Get("content-md5"), body)
		if err != nil {
			r.log.Error("validating content md5", "error", err.Error())
			http.Error(w, fmt.Sprintf("validating content md5: %s", err.Error()), http.StatusBadRequest)
			return
		}

		obj := object{
			kek:                       r.kek,
			client:                    client,
			key:                       key,
			bucket:                    bucket,
			data:                      body,
			query:                     req.URL.Query(),
			tags:                      req.Header.Get("x-amz-tagging"),
			contentType:               req.Header.Get("Content-Type"),
			metadata:                  metadata,
			objectLockLegalHoldStatus: req.Header.Get("x-amz-object-lock-legal-hold"),
			objectLockMode:            req.Header.Get("x-amz-object-lock-mode"),
			objectLockRetainUntilDate: retentionTime,
			sseCustomerAlgorithm:      req.Header.Get("x-amz-server-side-encryption-customer-algorithm"),
			sseCustomerKey:            req.Header.Get("x-amz-server-side-encryption-customer-key"),
			sseCustomerKeyMD5:         req.Header.Get("x-amz-server-side-encryption-customer-key-MD5"),
			log:                       r.log,
		}

		h = put(obj.put)

	case !containsBucket(req.Host) && match(path, "/([^/?]+)/(.+)", &bucket, &key) && req.Method == "PUT" && !isUnwantedPutEndpoint(req.Header, req.URL.Query()):
		r.log.Debug("intercepting", "path", req.URL.Path, "method", req.Method, "host", req.Host)
		body, err := io.ReadAll(req.Body)
		if err != nil {
			r.log.Error("PutObject", "error", err)
			http.Error(w, fmt.Sprintf("reading body: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		clientDigest := req.Header.Get("x-amz-content-sha256")
		serverDigest := sha256sum(body)

		// There may be a client that wants to test that incorrect content digests result in API errors.
		// For encrypting the body we have to recalculate the content digest.
		// If the client intentionally sends a mismatching content digest, we would take the client request, rewrap it,
		// calculate the correct digest for the new body and NOT get an error.
		// Thus we have to check incoming requets for matching content digests.
		// UNSIGNED-PAYLOAD can be used to disabled payload signing. In that case we don't check the content digest.
		if clientDigest != "" && clientDigest != "UNSIGNED-PAYLOAD" && clientDigest != serverDigest {
			r.log.Debug("PutObject", "error", "x-amz-content-sha256 mismatch")
			// The S3 API responds with an XML formatted error message.
			mismatchErr := NewContentSHA256MismatchError(clientDigest, serverDigest)
			marshalled, err := xml.Marshal(mismatchErr)
			if err != nil {
				r.log.Error("PutObject", "error", err)
				http.Error(w, fmt.Sprintf("marshalling error: %s", err.Error()), http.StatusInternalServerError)
				return
			}

			http.Error(w, string(marshalled), http.StatusBadRequest)
			return
		}

		metadata := getMetadataHeaders(req.Header)

		raw := req.Header.Get("x-amz-object-lock-retain-until-date")
		retentionTime, err := parseRetentionTime(raw)
		if err != nil {
			r.log.Error("parsing lock retention time", "data", raw, "error", err.Error())
			http.Error(w, fmt.Sprintf("parsing x-amz-object-lock-retain-until-date: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		err = validateContentMD5(req.Header.Get("content-md5"), body)
		if err != nil {
			r.log.Error("validating content md5", "error", err.Error())
			http.Error(w, fmt.Sprintf("validating content md5: %s", err.Error()), http.StatusBadRequest)
			return
		}

		obj := object{
			kek:                       r.kek,
			client:                    client,
			key:                       key,
			bucket:                    bucket,
			data:                      body,
			query:                     req.URL.Query(),
			tags:                      req.Header.Get("x-amz-tagging"),
			contentType:               req.Header.Get("Content-Type"),
			metadata:                  metadata,
			objectLockLegalHoldStatus: req.Header.Get("x-amz-object-lock-legal-hold"),
			objectLockMode:            req.Header.Get("x-amz-object-lock-mode"),
			objectLockRetainUntilDate: retentionTime,
			sseCustomerAlgorithm:      req.Header.Get("x-amz-server-side-encryption-customer-algorithm"),
			sseCustomerKey:            req.Header.Get("x-amz-server-side-encryption-customer-key"),
			sseCustomerKeyMD5:         req.Header.Get("x-amz-server-side-encryption-customer-key-MD5"),
			log:                       r.log,
		}

		h = put(obj.put)

	// Forward all other requests.
	default:
		r.log.Debug("forwarding", "path", req.URL.Path, "method", req.Method, "host", req.Host, "headers", req.Header)

		newReq := repackage(req)

		httpClient := http.DefaultClient
		resp, err := httpClient.Do(&newReq)
		if err != nil {
			r.log.Error("do request", "error", err)
			http.Error(w, fmt.Sprintf("do request: %s", err.Error()), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		for key := range resp.Header {
			w.Header().Set(key, resp.Header.Get(key))
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			r.log.Error("ReadAll", "error", err)
			http.Error(w, fmt.Sprintf("reading body: %s", err.Error()), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(resp.StatusCode)
		if body == nil {
			return
		}

		if _, err := w.Write(body); err != nil {
			r.log.Error("Write", "error", err)
			http.Error(w, fmt.Sprintf("writing body: %s", err.Error()), http.StatusInternalServerError)
			return
		}
		return
	}
	h.ServeHTTP(w, req)
}

// ContentSHA256MismatchError is a helper struct to create an XML formatted error message.
// s3 clients might try to parse error messages, so we need to serve correctly formatted messages.
type ContentSHA256MismatchError struct {
	XMLName                     xml.Name `xml:"Error"`
	Code                        string   `xml:"Code"`
	Message                     string   `xml:"Message"`
	ClientComputedContentSHA256 string   `xml:"ClientComputedContentSHA256"`
	S3ComputedContentSHA256     string   `xml:"S3ComputedContentSHA256"`
}

// NewContentSHA256MismatchError creates a new ContentSHA256MismatchError.
func NewContentSHA256MismatchError(clientComputedContentSHA256, s3ComputedContentSHA256 string) ContentSHA256MismatchError {
	return ContentSHA256MismatchError{
		Code:                        "XAmzContentSHA256Mismatch",
		Message:                     "The provided 'x-amz-content-sha256' header does not match what was computed.",
		ClientComputedContentSHA256: clientComputedContentSHA256,
		S3ComputedContentSHA256:     s3ComputedContentSHA256,
	}
}

// containsBucket is a helper to recognizes cases where the bucket name is sent as part of the host.
// In other cases the bucket name is sent as part of the path.
func containsBucket(host string) bool {
	parts := strings.Split(host, ".")
	return len(parts) > 4
}

// isGetObjectX returns true if the request is any of these requests: GetObjectAcl, GetObjectAttributes, GetObjectLegalHold, GetObjectRetention, GetObjectTagging, GetObjectTorrent, ListParts.
// These requests are all structured similarly: they all have a query param that is not present in GetObject.
// Otherwise those endpoints are similar to GetObject.
func isGetObjectX(query url.Values) bool {
	_, acl := query["acl"]
	_, attributes := query["attributes"]
	_, legalHold := query["legal-hold"]
	_, retention := query["retention"]
	_, tagging := query["tagging"]
	_, torrent := query["torrent"]
	_, uploadID := query["uploadId"]

	return acl || attributes || legalHold || retention || tagging || torrent || uploadID
}

// isUnwantedPutEndpoint returns true if the request is any of these requests: UploadPart, PutObjectTagging.
// These requests are all structured similarly: they all have a query param that is not present in PutObject.
// Otherwise those endpoints are similar to PutObject.
func isUnwantedPutEndpoint(header http.Header, query url.Values) bool {
	if header.Get("x-amz-copy-source") != "" {
		return true
	}

	_, partNumber := query["partNumber"]
	_, uploadID := query["uploadId"]
	_, tagging := query["tagging"]
	_, legalHold := query["legal-hold"]
	_, objectLock := query["object-lock"]
	_, retention := query["retention"]
	_, publicAccessBlock := query["publicAccessBlock"]
	_, acl := query["acl"]

	return partNumber || uploadID || tagging || legalHold || objectLock || retention || publicAccessBlock || acl
}

func sha256sum(data []byte) string {
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest)
}

// getMetadataHeaders parses user-defined metadata headers from a
// http.Header object. Users can define custom headers by taking
// HEADERNAME and prefixing it with "x-amz-meta-".
func getMetadataHeaders(header http.Header) map[string]string {
	result := map[string]string{}

	for key := range header {
		key = strings.ToLower(key)

		if strings.HasPrefix(key, "x-amz-meta-") {
			name := strings.TrimPrefix(key, "x-amz-meta-")
			result[name] = strings.Join(header.Values(key), ",")
		}
	}

	return result
}

func parseRetentionTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, raw)
}

// repackage implements all modifications we need to do to an incoming request that we want to forward to the s3 API.
func repackage(r *http.Request) http.Request {
	req := r.Clone(r.Context())

	// HTTP clients are not supposed to set this field, however when we receive a request it is set.
	// So, we unset it.
	req.RequestURI = ""

	req.URL.Host = r.Host
	// We always want to use HTTPS when talking to S3.
	req.URL.Scheme = "https"

	return *req
}

// validateContentMD5 checks if the content-md5 header matches the body.
func validateContentMD5(contentMD5 string, body []byte) error {
	if contentMD5 == "" {
		return nil
	}

	expected, err := base64.StdEncoding.DecodeString(contentMD5)
	if err != nil {
		return fmt.Errorf("decoding base64: %w", err)
	}

	if len(expected) != 16 {
		return fmt.Errorf("content-md5 must be 16 bytes long, got %d bytes", len(expected))
	}

	actual := md5.Sum(body)

	if !bytes.Equal(actual[:], expected) {
		return fmt.Errorf("content-md5 mismatch, header is %x, body is %x", expected, actual)
	}

	return nil
}

// match reports whether path matches pattern, and if it matches,
// assigns any capture groups to the *string or *int vars.
func match(path, pattern string, vars ...interface{}) bool {
	regex := mustCompileCached(pattern)
	matches := regex.FindStringSubmatch(path)
	if len(matches) <= 0 {
		return false
	}
	for i, match := range matches[1:] {
		switch p := vars[i].(type) {
		case *string:
			*p = match
		case *int:
			n, err := strconv.Atoi(match)
			if err != nil {
				return false
			}
			*p = n
		default:
			panic("vars must be *string or *int")
		}
	}
	return true
}

func mustCompileCached(pattern string) *regexp.Regexp {
	relock.Lock()
	defer relock.Unlock()

	regex := regexen[pattern]
	if regex == nil {
		regex = regexp.MustCompile("^" + pattern + "$")
		regexen[pattern] = regex
	}
	return regex
}

// allowMethod takes a HandlerFunc and wraps it in a handler that only
// responds if the request method is the given method, otherwise it
// responds with HTTP 405 Method Not Allowed.
func allowMethod(h http.HandlerFunc, method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if method != r.Method {
			w.Header().Set("Allow", method)
			http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

// get takes a HandlerFunc and wraps it to only allow the GET method.
func get(h http.HandlerFunc) http.HandlerFunc {
	return allowMethod(h, "GET")
}

// put takes a HandlerFunc and wraps it to only allow the POST method.
func put(h http.HandlerFunc) http.HandlerFunc {
	return allowMethod(h, "PUT")
}
