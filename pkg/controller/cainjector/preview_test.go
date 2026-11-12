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
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	admissionreg "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// Non-PEM byte fixtures: the CAInjectorMerging feature gate cannot parse them,
// so SetCA deterministically falls back to replacing the bundle with the
// source data. This keeps the tests independent of the feature gate state.
var (
	oldCA = []byte("prefix-OLD-CA-suffix")
	newCA = []byte("prefix-NEW-CA-suffix")
)

// fakeCADataSource is a configurable, in-memory caDataSource. It never touches
// the API.
type fakeCADataSource struct {
	configured bool
	ca         []byte
	readErr    error
	delay      time.Duration
}

func (f *fakeCADataSource) Configured(_ logr.Logger, _ metav1.Object) bool {
	return f.configured
}

func (f *fakeCADataSource) ReadCA(_ context.Context, _ logr.Logger, _ metav1.Object, _ string, _ sets.Set[string]) ([]byte, error) {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return f.ca, f.readErr
}

func newValidatingWebhookTarget(name string, annotations map[string]string, bundles ...[]byte) *admissionreg.ValidatingWebhookConfiguration {
	webhooks := make([]admissionreg.ValidatingWebhook, 0, len(bundles))
	for i, bundle := range bundles {
		webhooks = append(webhooks, admissionreg.ValidatingWebhook{
			Name:         fmt.Sprintf("webhook-%d", i),
			ClientConfig: admissionreg.WebhookClientConfig{CABundle: bundle},
		})
	}

	return &admissionreg.ValidatingWebhookConfiguration{
		Name:              name,
		ResourceVersion:   "rv-1",
		Annotations:       annotations,
		CreationTimestamp: metav1.Time{Time: time.Now()},
		Webhooks:          webhooks,
	}
}

func newMutatingWebhookTarget(name string, annotations map[string]string, bundles ...[]byte) *admissionreg.MutatingWebhookConfiguration {
	webhooks := make([]admissionreg.MutatingWebhook, 0, len(bundles))
	for i, bundle := range bundles {
		webhooks = append(webhooks, admissionreg.MutatingWebhook{
			Name:         fmt.Sprintf("webhook-%d", i),
			ClientConfig: admissionreg.WebhookClientConfig{CABundle: bundle},
		})
	}

	return &admissionreg.MutatingWebhookConfiguration{
		Name:            name,
		ResourceVersion: "rv-1",
		Annotations:     annotations,
		Webhooks:        webhooks,
	}
}

func newAPIServiceTarget(name string, annotations map[string]string, bundle []byte) *apireg.APIService {
	return &apireg.APIService{
		Name:            name,
		ResourceVersion: "rv-1",
		Annotations:     annotations,
		Spec:            apireg.APIServiceSpec{CABundle: bundle},
	}
}

func newCRDTarget(name string, annotations map[string]string, bundle []byte, withConversion bool) *apiext.CustomResourceDefinition {
	crd := &apiext.CustomResourceDefinition{
		Name:            name,
		ResourceVersion: "rv-1",
		Annotations:     annotations,
	}

	if withConversion {
		crd.Spec.Conversion = &apiext.CustomResourceConversion{
			Strategy: apiext.WebhookConverter,
			Webhook: &apiext.WebhookConversion{
				ClientConfig: &apiext.WebhookClientConfig{CABundle: bundle},
			},
		}
	}

	return crd
}

func TestDiffByteRanges(t *testing.T) {
	tests := []struct {
		name            string
		current         []byte
		desired         []byte
		expectedChanged bool
		expectedCurrent ByteRange
		expectedDesired ByteRange
	}{
		{
			name:            "identical bundles do not change",
			current:         []byte("prefix-OLD-CA-suffix"),
			desired:         []byte("prefix-OLD-CA-suffix"),
			expectedChanged: false,
		},
		{
			name:            "middle replacement keeps prefix and suffix",
			current:         []byte("abcOLDxyz"),
			desired:         []byte("abcNEWxyz"),
			expectedChanged: true,
			expectedCurrent: ByteRange{Offset: 3, Length: 3},
			expectedDesired: ByteRange{Offset: 3, Length: 3},
		},
		{
			name:            "insertion into empty bundle",
			current:         nil,
			desired:         []byte("abc"),
			expectedChanged: true,
			expectedCurrent: ByteRange{Offset: 0, Length: 0},
			expectedDesired: ByteRange{Offset: 0, Length: 3},
		},
		{
			name:            "deletion of the whole bundle",
			current:         []byte("abc"),
			desired:         nil,
			expectedChanged: true,
			expectedCurrent: ByteRange{Offset: 0, Length: 3},
			expectedDesired: ByteRange{Offset: 0, Length: 0},
		},
		{
			name:            "full replacement without common bytes",
			current:         []byte("OLD"),
			desired:         []byte("NEW-CONTENT"),
			expectedChanged: true,
			expectedCurrent: ByteRange{Offset: 0, Length: 3},
			expectedDesired: ByteRange{Offset: 0, Length: 11},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			currentRange, desiredRange, changed := diffByteRanges(tt.current, tt.desired)
			if changed != tt.expectedChanged {
				t.Fatalf("expected changed=%t, got %t", tt.expectedChanged, changed)
			}
			if !changed {
				return
			}
			if currentRange != tt.expectedCurrent {
				t.Errorf("expected current range %+v, got %+v", tt.expectedCurrent, currentRange)
			}
			if desiredRange != tt.expectedDesired {
				t.Errorf("expected desired range %+v, got %+v", tt.expectedDesired, desiredRange)
			}
		})
	}
}

func TestPreviewer_Preview_SkipReasons(t *testing.T) {
	secretAnnotation := map[string]string{cmapi.WantInjectFromSecretAnnotation: "ns1/secret1"}

	forbiddenErr := apierrors.NewForbidden(corev1.Resource("secrets"), "secret1", errors.New("denied"))
	notFoundErr := apierrors.NewNotFound(corev1.Resource("secrets"), "secret1")
	genericErr := errors.New("boom")

	tests := []struct {
		name           string
		target         client.Object
		source         *fakeCADataSource
		expectedReason SkipReason
		expectErr      bool
		errPredicate   func(error) bool
	}{
		{
			name: "target being deleted is skipped",
			target: func() client.Object {
				obj := newValidatingWebhookTarget("deleting", secretAnnotation, oldCA)
				obj.DeletionTimestamp = &metav1.Time{Time: time.Now()}
				return obj
			}(),
			source:         &fakeCADataSource{configured: true, ca: newCA},
			expectedReason: SkipReasonDeleting,
		},
		{
			name:           "target without injection annotation has no data source",
			target:         newValidatingWebhookTarget("unannotated", nil, oldCA),
			source:         &fakeCADataSource{configured: false, ca: newCA},
			expectedReason: SkipReasonNoDataSource,
		},
		{
			name: "malformed secret annotation is invalid",
			target: newValidatingWebhookTarget("bad-annotation", map[string]string{
				cmapi.WantInjectFromSecretAnnotation: "missing-namespace",
			}, oldCA),
			source:         &fakeCADataSource{configured: false},
			expectedReason: SkipReasonInvalidAnnotation,
		},
		{
			name: "malformed certificate annotation is invalid",
			target: newValidatingWebhookTarget("bad-annotation", map[string]string{
				cmapi.WantInjectAnnotation: "missing-namespace",
			}, oldCA),
			source:         &fakeCADataSource{configured: false},
			expectedReason: SkipReasonInvalidAnnotation,
		},
		{
			name: "apiserver annotation must be true",
			target: newValidatingWebhookTarget("bad-annotation", map[string]string{
				cmapi.WantInjectAPIServerCAAnnotation: "yes",
			}, oldCA),
			source:         &fakeCADataSource{configured: false},
			expectedReason: SkipReasonInvalidAnnotation,
		},
		{
			name:           "forbidden source keeps a diagnosable error",
			target:         newValidatingWebhookTarget("forbidden", secretAnnotation, oldCA),
			source:         &fakeCADataSource{configured: true, readErr: forbiddenErr},
			expectedReason: SkipReasonSourceForbidden,
			expectErr:      true,
			errPredicate:   apierrors.IsForbidden,
		},
		{
			name:           "missing source is reported as not found",
			target:         newValidatingWebhookTarget("missing", secretAnnotation, oldCA),
			source:         &fakeCADataSource{configured: true, readErr: notFoundErr},
			expectedReason: SkipReasonSourceNotFound,
			expectErr:      true,
			errPredicate:   apierrors.IsNotFound,
		},
		{
			name:           "unexpected source error is retained",
			target:         newValidatingWebhookTarget("error", secretAnnotation, oldCA),
			source:         &fakeCADataSource{configured: true, readErr: genericErr},
			expectedReason: SkipReasonSourceError,
			expectErr:      true,
			errPredicate:   func(err error) bool { return errors.Is(err, genericErr) },
		},
		{
			name:           "source without CA data is not ready",
			target:         newValidatingWebhookTarget("not-ready", secretAnnotation, oldCA),
			source:         &fakeCADataSource{configured: true, ca: nil},
			expectedReason: SkipReasonSourceNotReady,
		},
		{
			name:           "up to date target is unchanged",
			target:         newValidatingWebhookTarget("unchanged", secretAnnotation, oldCA),
			source:         &fakeCADataSource{configured: true, ca: oldCA},
			expectedReason: SkipReasonUnchanged,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			previewer := NewPreviewer(
				ValidatingWebhookConfigurationName,
				newValidatingWebhookInjectable,
				[]caDataSource{tt.source},
				PreviewOptions{Logger: logr.Discard()},
			)

			results := previewer.Preview(t.Context(), []client.Object{tt.target})
			if len(results) != 1 {
				t.Fatalf("expected exactly one result, got %d", len(results))
			}
			result := results[0]

			if result.SkipReason != tt.expectedReason {
				t.Fatalf("expected skip reason %q, got %q (message: %q)",
					tt.expectedReason, result.SkipReason, result.Message)
			}
			if len(result.Changes) != 0 {
				t.Errorf("expected no changes for skipped target, got %d", len(result.Changes))
			}
			if tt.expectErr {
				if result.Err == nil {
					t.Fatal("expected a diagnosable error, got nil")
				}
				if tt.errPredicate != nil && !tt.errPredicate(result.Err) {
					t.Fatalf("error predicate failed for %v", result.Err)
				}
				var sourceErr *SourceError
				if !errors.As(result.Err, &sourceErr) {
					t.Fatalf("expected *SourceError, got %T", result.Err)
				}
				if sourceErr.AnnotationKey != cmapi.WantInjectFromSecretAnnotation {
					t.Errorf("expected annotation key %q, got %q",
						cmapi.WantInjectFromSecretAnnotation, sourceErr.AnnotationKey)
				}
			} else if result.Err != nil {
				t.Errorf("expected no error, got %v", result.Err)
			}
		})
	}
}

func TestPreviewer_Preview_ValidatingWebhookChange(t *testing.T) {
	target := newValidatingWebhookTarget("vwc",
		map[string]string{cmapi.WantInjectFromSecretAnnotation: "ns1/secret1"}, oldCA)
	source := &fakeCADataSource{configured: true, ca: newCA}
	previewer := NewPreviewer(
		ValidatingWebhookConfigurationName,
		newValidatingWebhookInjectable,
		[]caDataSource{source},
		PreviewOptions{},
	)

	result := previewer.Preview(t.Context(), []client.Object{target})[0]

	if result.SkipReason != "" {
		t.Fatalf("expected an updatable target, got skip reason %q: %s", result.SkipReason, result.Message)
	}
	if result.Kind != ValidatingWebhookConfigurationName {
		t.Errorf("expected kind %q, got %q", ValidatingWebhookConfigurationName, result.Kind)
	}
	if result.ResourceVersion != "rv-1" {
		t.Errorf("expected resource version rv-1, got %q", result.ResourceVersion)
	}
	if result.AnnotationKey != cmapi.WantInjectFromSecretAnnotation || result.AnnotationValue != "ns1/secret1" {
		t.Errorf("unexpected annotation %s=%q", result.AnnotationKey, result.AnnotationValue)
	}
	// The in-memory fake source is unknown to dataSourceName, which falls back
	// to its Go type name. The well-known "secret" name is covered by the real
	// secretDataSource test below.
	if expectedName := dataSourceName(source); result.Source != expectedName {
		t.Errorf("expected source %q, got %q", expectedName, result.Source)
	}
	if result.SourceCALength != len(newCA) || result.SourceCASHA256 != sha256Hex(newCA) {
		t.Errorf("unexpected source CA fingerprint: len=%d sha256=%q", result.SourceCALength, result.SourceCASHA256)
	}

	if len(result.Changes) != 1 {
		t.Fatalf("expected one change, got %d", len(result.Changes))
	}
	change := result.Changes[0]
	expectedPath := "webhooks[0].clientConfig.caBundle"
	if change.FieldPath != expectedPath {
		t.Errorf("expected field path %q, got %q", expectedPath, change.FieldPath)
	}
	// "prefix-" (7 bytes) is the common prefix and "-CA-suffix" (10 bytes) the
	// common suffix, so only the 3-byte middle part is replaced.
	expectedRange := ByteRange{Offset: 7, Length: 3}
	if change.CurrentRange != expectedRange || change.DesiredRange != expectedRange {
		t.Errorf("unexpected ranges: current=%+v desired=%+v", change.CurrentRange, change.DesiredRange)
	}
	if change.CurrentLength != len(oldCA) || change.DesiredLength != len(newCA) {
		t.Errorf("unexpected bundle lengths: current=%d desired=%d", change.CurrentLength, change.DesiredLength)
	}
	if change.CurrentSHA256 != sha256Hex(oldCA) || change.DesiredSHA256 != sha256Hex(newCA) {
		t.Errorf("unexpected bundle digests: current=%q desired=%q", change.CurrentSHA256, change.DesiredSHA256)
	}

	// The caller's object must not be mutated.
	if string(target.Webhooks[0].ClientConfig.CABundle) != string(oldCA) {
		t.Errorf("input target was mutated: %q", target.Webhooks[0].ClientConfig.CABundle)
	}
}

func TestPreviewer_Preview_MultipleWebhooksStayOrdered(t *testing.T) {
	target := newMutatingWebhookTarget("mwc",
		map[string]string{cmapi.WantInjectFromSecretAnnotation: "ns1/secret1"}, oldCA, oldCA)
	previewer := NewPreviewer(
		MutatingWebhookConfigurationName,
		newMutatingWebhookInjectable,
		[]caDataSource{&fakeCADataSource{configured: true, ca: newCA}},
		PreviewOptions{},
	)

	result := previewer.Preview(t.Context(), []client.Object{target})[0]
	if len(result.Changes) != 2 {
		t.Fatalf("expected two changes, got %d", len(result.Changes))
	}

	expectedPaths := []string{
		"webhooks[0].clientConfig.caBundle",
		"webhooks[1].clientConfig.caBundle",
	}
	for i, expectedPath := range expectedPaths {
		if result.Changes[i].FieldPath != expectedPath {
			t.Errorf("change %d: expected path %q, got %q", i, expectedPath, result.Changes[i].FieldPath)
		}
	}

	for i := range target.Webhooks {
		if string(target.Webhooks[i].ClientConfig.CABundle) != string(oldCA) {
			t.Errorf("webhook %d of the input target was mutated", i)
		}
	}
}

func TestPreviewer_Preview_APIServiceAndCRD(t *testing.T) {
	annotations := map[string]string{cmapi.WantInjectFromSecretAnnotation: "ns1/secret1"}

	t.Run("APIService", func(t *testing.T) {
		target := newAPIServiceTarget("api", annotations, oldCA)
		previewer := NewPreviewer(
			APIServiceName,
			newAPIServiceInjectable,
			[]caDataSource{&fakeCADataSource{configured: true, ca: newCA}},
			PreviewOptions{},
		)

		result := previewer.Preview(t.Context(), []client.Object{target})[0]
		if len(result.Changes) != 1 {
			t.Fatalf("expected one change, got %d", len(result.Changes))
		}
		if result.Changes[0].FieldPath != "spec.caBundle" {
			t.Errorf("unexpected field path %q", result.Changes[0].FieldPath)
		}
		if string(target.Spec.CABundle) != string(oldCA) {
			t.Error("input target was mutated")
		}
	})

	t.Run("CRD with conversion webhook", func(t *testing.T) {
		target := newCRDTarget("crd", annotations, oldCA, true)
		previewer := NewPreviewer(
			CustomResourceDefinitionName,
			newCRDConversionInjectable,
			[]caDataSource{&fakeCADataSource{configured: true, ca: newCA}},
			PreviewOptions{},
		)

		result := previewer.Preview(t.Context(), []client.Object{target})[0]
		if len(result.Changes) != 1 {
			t.Fatalf("expected one change, got %d", len(result.Changes))
		}
		expectedPath := "spec.conversion.webhook.clientConfig.caBundle"
		if result.Changes[0].FieldPath != expectedPath {
			t.Errorf("unexpected field path %q", result.Changes[0].FieldPath)
		}
	})

	t.Run("CRD without conversion webhook has no CA fields", func(t *testing.T) {
		target := newCRDTarget("crd", annotations, oldCA, false)
		previewer := NewPreviewer(
			CustomResourceDefinitionName,
			newCRDConversionInjectable,
			[]caDataSource{&fakeCADataSource{configured: true, ca: newCA}},
			PreviewOptions{},
		)

		result := previewer.Preview(t.Context(), []client.Object{target})[0]
		if result.SkipReason != SkipReasonUnchanged {
			t.Fatalf("expected %q, got %q: %s", SkipReasonUnchanged, result.SkipReason, result.Message)
		}
		if len(result.Changes) != 0 {
			t.Errorf("expected no changes, got %d", len(result.Changes))
		}
	})
}

func TestPreviewer_Preview_EmptyInput(t *testing.T) {
	previewer := NewPreviewer(
		ValidatingWebhookConfigurationName,
		newValidatingWebhookInjectable,
		[]caDataSource{&fakeCADataSource{configured: true, ca: newCA}},
		PreviewOptions{},
	)

	results := previewer.Preview(t.Context(), nil)
	if len(results) != 0 {
		t.Fatalf("expected empty result slice, got %d", len(results))
	}
}

func TestPreviewer_Preview_ConcurrentInputIsStable(t *testing.T) {
	const targetCount = 25

	buildTargets := func() []client.Object {
		targets := make([]client.Object, targetCount)
		for i := range targets {
			targets[i] = newValidatingWebhookTarget(
				fmt.Sprintf("target-%02d", i),
				map[string]string{cmapi.WantInjectFromSecretAnnotation: "ns1/secret1"},
				oldCA,
			)
		}
		return targets
	}

	// Delays scramble goroutine completion order on purpose.
	source := &fakeCADataSource{
		configured: true,
		ca:         newCA,
		delay:      2 * time.Millisecond,
	}
	previewer := NewPreviewer(
		ValidatingWebhookConfigurationName,
		newValidatingWebhookInjectable,
		[]caDataSource{source},
		PreviewOptions{Concurrency: 4},
	)

	for iteration := range 5 {
		targets := buildTargets()
		results := previewer.Preview(t.Context(), targets)

		if len(results) != targetCount {
			t.Fatalf("iteration %d: expected %d results, got %d", iteration, targetCount, len(results))
		}

		for i, result := range results {
			expectedName := fmt.Sprintf("target-%02d", i)
			if result.NamespacedName.Name != expectedName {
				t.Fatalf("iteration %d: result at index %d is %q, expected %q; output ordering is unstable",
					iteration, i, result.NamespacedName.Name, expectedName)
			}
			if result.ResourceVersion != "rv-1" {
				t.Errorf("iteration %d: lost resource version for %s", iteration, expectedName)
			}
			if len(result.Changes) != 1 {
				t.Fatalf("iteration %d: expected one change for %s, got %d",
					iteration, expectedName, len(result.Changes))
			}
			expectedRange := ByteRange{Offset: 7, Length: 3}
			if result.Changes[0].CurrentRange != expectedRange || result.Changes[0].DesiredRange != expectedRange {
				t.Errorf("iteration %d: unexpected ranges for %s: %+v / %+v",
					iteration, expectedName, result.Changes[0].CurrentRange, result.Changes[0].DesiredRange)
			}
		}

		// All inputs must remain untouched regardless of concurrent processing.
		for i, obj := range targets {
			target := obj.(*admissionreg.ValidatingWebhookConfiguration)
			if string(target.Webhooks[0].ClientConfig.CABundle) != string(oldCA) {
				t.Fatalf("iteration %d: input target %d was mutated", iteration, i)
			}
		}
	}
}

func TestPreviewer_Preview_RealSecretDataSource(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))

	secret := &corev1.Secret{
		Namespace: "ns1",
		Name:      "secret1",
		Annotations: map[string]string{
			cmapi.AllowsInjectionFromSecretAnnotation: "true",
		},
		Data: map[string][]byte{cmmeta.TLSCAKey: newCA},
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	t.Run("existing secret produces a change", func(t *testing.T) {
		previewer := NewPreviewer(
			ValidatingWebhookConfigurationName,
			newValidatingWebhookInjectable,
			[]caDataSource{&secretDataSource{client: cl}},
			PreviewOptions{},
		)
		target := newValidatingWebhookTarget("vwc",
			map[string]string{cmapi.WantInjectFromSecretAnnotation: "ns1/secret1"}, oldCA)

		result := previewer.Preview(t.Context(), []client.Object{target})[0]
		if result.SkipReason != "" {
			t.Fatalf("expected change, got skip reason %q: %s", result.SkipReason, result.Message)
		}
		if result.Source != "secret" {
			t.Errorf("expected secret source, got %q", result.Source)
		}
		if len(result.Changes) != 1 {
			t.Fatalf("expected one change, got %d", len(result.Changes))
		}
	})

	t.Run("missing secret is reported as not ready", func(t *testing.T) {
		emptyClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		previewer := NewPreviewer(
			ValidatingWebhookConfigurationName,
			newValidatingWebhookInjectable,
			[]caDataSource{&secretDataSource{client: emptyClient}},
			PreviewOptions{},
		)
		target := newValidatingWebhookTarget("vwc",
			map[string]string{cmapi.WantInjectFromSecretAnnotation: "ns1/missing"}, oldCA)

		result := previewer.Preview(t.Context(), []client.Object{target})[0]
		// The production secretDataSource intentionally drops NotFound errors
		// via dropNotFound and returns (nil, nil) instead, so the previewer
		// surfaces this as "not ready". Errors that the source does propagate
		// (forbidden, unexpected) are retained verbatim, see TestPreviewer_Preview_SkipReasons.
		if result.SkipReason != SkipReasonSourceNotReady {
			t.Fatalf("expected %q, got %q (err: %v)", SkipReasonSourceNotReady, result.SkipReason, result.Err)
		}
	})
}
