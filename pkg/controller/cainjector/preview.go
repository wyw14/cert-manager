/*
Copyright The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cainjector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	admissionreg "k8s.io/api/admissionregistration/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// This file contains a read-only "change preview" for cainjector injectables.
// Unlike the reconciler, the previewer never writes to the Kubernetes API: it
// only reads CA data through the configured (read-only) data sources and
// computes, in memory, which CA fields of which targets would change and which
// targets would be skipped, together with the reason why.

// defaultPreviewConcurrency bounds the number of targets whose CA sources are
// read in parallel.
const defaultPreviewConcurrency = 4

// ByteRange describes a contiguous, half-open range of bytes inside a CA
// bundle: it covers the bytes at offsets Offset through Offset+Length-1.
type ByteRange struct {
	// Offset is the zero-based index of the first byte in the range.
	Offset int `json:"offset"`
	// Length is the number of bytes covered by the range. A zero length means
	// that the range is an insertion at Offset.
	Length int `json:"length"`
}

// SkipReason describes why a target would be skipped, i.e. why no API write is
// required (or why no preview could be computed) for it.
type SkipReason string

const (
	// SkipReasonDeleting indicates that the target object is being deleted.
	SkipReasonDeleting SkipReason = "Deleting"
	// SkipReasonNoDataSource indicates that the target carries no injection
	// annotation selecting a CA data source.
	SkipReasonNoDataSource SkipReason = "NoDataSource"
	// SkipReasonInvalidAnnotation indicates that an injection annotation is
	// present but malformed.
	SkipReasonInvalidAnnotation SkipReason = "InvalidAnnotation"
	// SkipReasonSourceForbidden indicates that reading the CA data source was
	// forbidden.
	SkipReasonSourceForbidden SkipReason = "SourceForbidden"
	// SkipReasonSourceNotFound indicates that the referenced CA data source
	// (or the secret backing it) does not exist yet.
	SkipReasonSourceNotFound SkipReason = "SourceNotFound"
	// SkipReasonSourceNotReady indicates that the source exists but currently
	// exposes no CA data.
	SkipReasonSourceNotReady SkipReason = "SourceNotReady"
	// SkipReasonSourceError indicates that reading the CA data source failed
	// with an unexpected error.
	SkipReasonSourceError SkipReason = "SourceError"
	// SkipReasonUnchanged indicates that every CA field already contains the
	// desired CA bundle, so no API write would be required.
	SkipReasonUnchanged SkipReason = "Unchanged"
)

// CAFieldChange describes the byte ranges that differ between the current CA
// bundle and the desired CA bundle of a single CA field within a target.
type CAFieldChange struct {
	// FieldPath identifies the CA field within the target object, for example
	// "webhooks[0].clientConfig.caBundle" or "spec.caBundle".
	FieldPath string `json:"fieldPath"`
	// CurrentRange is the byte range of the current CA bundle that would be
	// replaced.
	CurrentRange ByteRange `json:"currentRange"`
	// DesiredRange is the byte range of the desired CA bundle that would
	// replace the current range.
	DesiredRange ByteRange `json:"desiredRange"`
	// CurrentLength is the total length of the current CA bundle in bytes.
	CurrentLength int `json:"currentLength"`
	// DesiredLength is the total length of the desired CA bundle in bytes.
	DesiredLength int `json:"desiredLength"`
	// CurrentSHA256 is the hex-encoded SHA-256 digest of the current bundle.
	CurrentSHA256 string `json:"currentSHA256"`
	// DesiredSHA256 is the hex-encoded SHA-256 digest of the desired bundle.
	DesiredSHA256 string `json:"desiredSHA256"`
}

// SourceError wraps an error returned while reading a CA data source so that
// the failing source and the annotation that selected it stay diagnosable.
// It unwraps to the underlying error, which means apierrors.IsNotFound and
// apierrors.IsForbidden keep working on a SourceError.
type SourceError struct {
	// Source names the data source that failed (for example "secret",
	// "certificate" or "apiserver-ca").
	Source string
	// AnnotationKey is the injection annotation that selected the source.
	AnnotationKey string
	// AnnotationValue is the raw value of the injection annotation.
	AnnotationValue string
	// Err is the error returned by the data source.
	Err error
}

func (e *SourceError) Error() string {
	return fmt.Sprintf(
		"cainjector preview: failed to read CA from source %q (annotation %s=%q): %v",
		e.Source, e.AnnotationKey, e.AnnotationValue, e.Err,
	)
}

// Unwrap exposes the underlying data source error.
func (e *SourceError) Unwrap() error {
	return e.Err
}

// PreviewResult is the read-only change preview computed for a single target.
type PreviewResult struct {
	// Kind is the injectable kind (for example "validatingwebhookconfiguration").
	Kind string
	// NamespacedName identifies the target object.
	NamespacedName types.NamespacedName
	// ResourceVersion is the resourceVersion of the target object that was
	// previewed. It lets callers detect concurrent modifications before
	// applying anything themselves.
	ResourceVersion string
	// AnnotationKey is the injection annotation present on the target, if any.
	AnnotationKey string
	// AnnotationValue is the raw value of the injection annotation.
	AnnotationValue string
	// Source names the selected CA data source, if any.
	Source string
	// SourceCALength is the length of the CA bundle read from the source.
	SourceCALength int
	// SourceCASHA256 is the hex-encoded SHA-256 digest of the source CA bundle.
	SourceCASHA256 string
	// Changes lists, per CA field, the byte ranges that would have to be
	// updated. It is empty when SkipReason is set.
	Changes []CAFieldChange
	// SkipReason explains why the target would be skipped (or needs no
	// update). It is empty when Changes is non-empty.
	SkipReason SkipReason
	// Message provides human-readable detail about the skip reason.
	Message string
	// Err retains the diagnosable source error. It is only populated for the
	// SourceForbidden, SourceNotFound and SourceError skip reasons.
	Err error
}

// PreviewOptions configures a Previewer.
type PreviewOptions struct {
	// Namespace, when non-empty, restricts the readable CA sources to this
	// namespace. It mirrors the reconciler's namespace scope.
	Namespace string
	// IgnoreNamespaces is the set of namespaces whose CA sources must not be
	// read.
	IgnoreNamespaces sets.Set[string]
	// Concurrency bounds the number of targets previewed in parallel. Values
	// smaller than 1 fall back to the default concurrency.
	Concurrency int
	// Logger is used for diagnostic logging. It defaults to a discarding
	// logger.
	Logger logr.Logger
}

// Previewer computes read-only change previews for cainjector injectables.
// It never creates, updates, patches or deletes any API object: source CA data
// is read exclusively through the read-only caDataSource implementations, and
// the supplied target objects are always deep-copied before being mutated in
// memory.
type Previewer struct {
	resourceName        string
	newInjectableTarget NewInjectableTarget
	sources             []caDataSource
	namespace           string
	ignoreNamespaces    sets.Set[string]
	concurrency         int
	log                 logr.Logger
}

// NewPreviewer builds a Previewer for one injectable kind. The arguments mirror
// those of the reconciler so that both can be wired from the same setup.
func NewPreviewer(resourceName string, newTarget NewInjectableTarget, sources []caDataSource, opts PreviewOptions) *Previewer {
	concurrency := opts.Concurrency
	if concurrency < 1 {
		concurrency = defaultPreviewConcurrency
	}

	log := opts.Logger
	if log.IsZero() {
		log = logr.Discard()
	}

	return &Previewer{
		resourceName:        resourceName,
		newInjectableTarget: newTarget,
		sources:             sources,
		namespace:           opts.Namespace,
		ignoreNamespaces:    opts.IgnoreNamespaces,
		concurrency:         concurrency,
		log:                 log,
	}
}

// Preview computes a change preview for every supplied target. The returned
// slice always has the same length and ordering as targets: each result is
// written to the index of its input, so processing targets concurrently is
// deterministic and involves no shared mutable state.
//
// Preview is read-only: the only API calls it can trigger are the Get/List
// reads performed by the configured caDataSources, and the supplied target
// objects are never mutated.
func (p *Previewer) Preview(ctx context.Context, targets []client.Object) []PreviewResult {
	results := make([]PreviewResult, len(targets))

	semaphore := make(chan struct{}, p.concurrency)
	var wg sync.WaitGroup
	for index, target := range targets {
		wg.Add(1)
		go func(i int, obj client.Object) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				results[i] = p.canceledResult(obj, ctx.Err())
				return
			}
			defer func() { <-semaphore }()

			results[i] = p.previewOne(ctx, obj)
		}(index, target)
	}
	wg.Wait()

	return results
}

// previewOne computes the preview for a single target. It does not mutate obj.
func (p *Previewer) previewOne(ctx context.Context, obj client.Object) PreviewResult {
	log := p.log.WithValues("kind", p.resourceName, "name", obj.GetName())
	result := p.baseResult(obj)

	// ignore resources that are being deleted, mirroring the reconciler
	if !obj.GetDeletionTimestamp().IsZero() {
		result.SkipReason = SkipReasonDeleting
		result.Message = "target object is being deleted"
		return result
	}

	annotationKey, annotationValue, annotationErr := injectionAnnotation(obj)
	result.AnnotationKey = annotationKey
	result.AnnotationValue = annotationValue
	if annotationErr != nil {
		result.SkipReason = SkipReasonInvalidAnnotation
		result.Message = annotationErr.Error()
		return result
	}

	source, err := caDataSourceFor(p.sources, log, obj)
	if err != nil {
		result.SkipReason = SkipReasonNoDataSource
		result.Message = err.Error()
		return result
	}
	result.Source = dataSourceName(source)

	caData, err := source.ReadCA(ctx, log, obj, p.namespace, p.ignoreNamespaces)
	if err != nil {
		sourceErr := &SourceError{
			Source:          result.Source,
			AnnotationKey:   annotationKey,
			AnnotationValue: annotationValue,
			Err:             err,
		}
		result.Err = sourceErr
		result.Message = sourceErr.Error()
		switch {
		case apierrors.IsForbidden(err):
			result.SkipReason = SkipReasonSourceForbidden
		case apierrors.IsNotFound(err):
			result.SkipReason = SkipReasonSourceNotFound
		default:
			result.SkipReason = SkipReasonSourceError
		}
		return result
	}
	if caData == nil {
		result.SkipReason = SkipReasonSourceNotReady
		result.Message = "CA data source returned no CA bundle"
		return result
	}
	result.SourceCALength = len(caData)
	result.SourceCASHA256 = sha256Hex(caData)

	// Build the desired state on a deep copy so that the caller's object is
	// never mutated. SetCA reproduces exactly the in-memory transformation the
	// reconciler would apply before its Apply call.
	desiredTarget, err := loadInjectableTarget(p.newInjectableTarget, obj)
	if err != nil {
		result.SkipReason = SkipReasonSourceError
		result.Message = err.Error()
		result.Err = err
		return result
	}
	desiredTarget.SetCA(caData)

	result.Changes = diffCAFields(obj, desiredTarget.AsObject())
	if len(result.Changes) == 0 {
		result.SkipReason = SkipReasonUnchanged
		result.Message = "all CA fields already contain the desired CA bundle"
	}

	return result
}

func (p *Previewer) baseResult(obj client.Object) PreviewResult {
	return PreviewResult{
		Kind: p.resourceName,
		NamespacedName: types.NamespacedName{
			Namespace: obj.GetNamespace(),
			Name:      obj.GetName(),
		},
		ResourceVersion: obj.GetResourceVersion(),
		// Ensure callers can rely on Changes being non-nil only when there is
		// something to update.
		Changes: nil,
	}
}

func (p *Previewer) canceledResult(obj client.Object, err error) PreviewResult {
	result := p.baseResult(obj)
	result.SkipReason = SkipReasonSourceError
	result.Message = "preview canceled before the CA data source could be read"
	result.Err = err
	return result
}

// injectionAnnotation returns the injection annotation selected for the
// object, following the same source priority as the reconciler (secret, then
// certificate, then apiserver CA). A non-nil error is returned when a present
// injection annotation is malformed.
func injectionAnnotation(obj metav1.Object) (key, value string, err error) {
	annotations := obj.GetAnnotations()

	if raw, ok := annotations[cmapi.WantInjectFromSecretAnnotation]; ok {
		if splitNamespacedName(raw).Namespace == "" {
			return cmapi.WantInjectFromSecretAnnotation, raw, fmt.Errorf(
				"invalid %s annotation %q: expected a namespace/name reference",
				cmapi.WantInjectFromSecretAnnotation, raw,
			)
		}
		return cmapi.WantInjectFromSecretAnnotation, raw, nil
	}

	if raw, ok := annotations[cmapi.WantInjectAnnotation]; ok {
		if splitNamespacedName(raw).Namespace == "" {
			return cmapi.WantInjectAnnotation, raw, fmt.Errorf(
				"invalid %s annotation %q: expected a namespace/name reference",
				cmapi.WantInjectAnnotation, raw,
			)
		}
		return cmapi.WantInjectAnnotation, raw, nil
	}

	if raw, ok := annotations[cmapi.WantInjectAPIServerCAAnnotation]; ok {
		if raw != "true" {
			return cmapi.WantInjectAPIServerCAAnnotation, raw, fmt.Errorf(
				"invalid %s annotation %q: value must be %q",
				cmapi.WantInjectAPIServerCAAnnotation, raw, "true",
			)
		}
		return cmapi.WantInjectAPIServerCAAnnotation, raw, nil
	}

	return "", "", nil
}

// dataSourceName returns a stable, human-readable name for a configured data
// source.
func dataSourceName(source caDataSource) string {
	switch source.(type) {
	case *secretDataSource:
		return "secret"
	case *certificateDataSource:
		return "certificate"
	case *kubeconfigDataSource:
		return "apiserver-ca"
	default:
		return fmt.Sprintf("%T", source)
	}
}

// loadInjectableTarget creates an InjectTarget populated with a deep copy of
// obj. The deep copy guarantees that the following SetCA call cannot mutate the
// caller's object.
func loadInjectableTarget(newTarget NewInjectableTarget, obj client.Object) (InjectTarget, error) {
	target := newTarget()

	switch dst := target.AsObject().(type) {
	case *admissionreg.MutatingWebhookConfiguration:
		src, ok := obj.(*admissionreg.MutatingWebhookConfiguration)
		if !ok {
			return nil, fmt.Errorf("expected *%T, got %T", dst, obj)
		}
		*dst = *src.DeepCopy()
	case *admissionreg.ValidatingWebhookConfiguration:
		src, ok := obj.(*admissionreg.ValidatingWebhookConfiguration)
		if !ok {
			return nil, fmt.Errorf("expected *%T, got %T", dst, obj)
		}
		*dst = *src.DeepCopy()
	case *apireg.APIService:
		src, ok := obj.(*apireg.APIService)
		if !ok {
			return nil, fmt.Errorf("expected *%T, got %T", dst, obj)
		}
		*dst = *src.DeepCopy()
	case *apiext.CustomResourceDefinition:
		src, ok := obj.(*apiext.CustomResourceDefinition)
		if !ok {
			return nil, fmt.Errorf("expected *%T, got %T", dst, obj)
		}
		*dst = *src.DeepCopy()
	default:
		return nil, fmt.Errorf("unsupported injectable target type %T", obj)
	}

	return target, nil
}

// caField is one CA bundle field extracted from an injectable object.
type caField struct {
	path string
	data []byte
}

// extractCAFields returns every CA bundle field of obj, in stable field order.
func extractCAFields(obj client.Object) []caField {
	switch o := obj.(type) {
	case *admissionreg.MutatingWebhookConfiguration:
		fields := make([]caField, 0, len(o.Webhooks))
		for i := range o.Webhooks {
			fields = append(fields, caField{
				path: fmt.Sprintf("webhooks[%d].clientConfig.caBundle", i),
				data: o.Webhooks[i].ClientConfig.CABundle,
			})
		}
		return fields
	case *admissionreg.ValidatingWebhookConfiguration:
		fields := make([]caField, 0, len(o.Webhooks))
		for i := range o.Webhooks {
			fields = append(fields, caField{
				path: fmt.Sprintf("webhooks[%d].clientConfig.caBundle", i),
				data: o.Webhooks[i].ClientConfig.CABundle,
			})
		}
		return fields
	case *apireg.APIService:
		return []caField{{
			path: "spec.caBundle",
			data: o.Spec.CABundle,
		}}
	case *apiext.CustomResourceDefinition:
		if o.Spec.Conversion == nil ||
			o.Spec.Conversion.Webhook == nil ||
			o.Spec.Conversion.Webhook.ClientConfig == nil {
			return nil
		}
		return []caField{{
			path: "spec.conversion.webhook.clientConfig.caBundle",
			data: o.Spec.Conversion.Webhook.ClientConfig.CABundle,
		}}
	default:
		return nil
	}
}

// diffCAFields compares matching CA fields of the current and desired objects
// and returns the byte ranges that differ, in field order.
func diffCAFields(current, desired client.Object) []CAFieldChange {
	currentFields := extractCAFields(current)
	desiredFields := extractCAFields(desired)

	changes := []CAFieldChange{}
	for i := range desiredFields {
		// desired is built from current, so the field sets always match; the
		// bound check only guards against unexpected target implementations.
		if i >= len(currentFields) {
			break
		}

		currentRange, desiredRange, changed := diffByteRanges(currentFields[i].data, desiredFields[i].data)
		if !changed {
			continue
		}

		changes = append(changes, CAFieldChange{
			FieldPath:     desiredFields[i].path,
			CurrentRange:  currentRange,
			DesiredRange:  desiredRange,
			CurrentLength: len(currentFields[i].data),
			DesiredLength: len(desiredFields[i].data),
			CurrentSHA256: sha256Hex(currentFields[i].data),
			DesiredSHA256: sha256Hex(desiredFields[i].data),
		})
	}

	return changes
}

// diffByteRanges locates the smallest single replacement that turns current
// into desired by trimming their common prefix and common suffix. When the two
// slices are equal it reports changed=false.
func diffByteRanges(current, desired []byte) (currentRange, desiredRange ByteRange, changed bool) {
	if bytes.Equal(current, desired) {
		return ByteRange{}, ByteRange{}, false
	}

	prefix := 0
	maxPrefix := min(len(current), len(desired))
	for prefix < maxPrefix && current[prefix] == desired[prefix] {
		prefix++
	}

	suffix := 0
	maxSuffix := min(len(current)-prefix, len(desired)-prefix)
	for suffix < maxSuffix &&
		current[len(current)-1-suffix] == desired[len(desired)-1-suffix] {
		suffix++
	}

	return ByteRange{Offset: prefix, Length: len(current) - prefix - suffix},
		ByteRange{Offset: prefix, Length: len(desired) - prefix - suffix},
		true
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
