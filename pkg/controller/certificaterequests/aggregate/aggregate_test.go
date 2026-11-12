/*
Copyright 2026 The cert-manager Authors.

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

package aggregate

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	fixedClockStart = time.Now()
	fixedClock      = clocktesting.NewFakeClock(fixedClockStart)
	nowMetaTime     = metav1.NewTime(fixedClockStart)
	oldMetaTime     = metav1.NewTime(fixedClockStart.Add(-time.Hour))
)

func setGeneration(generation int64) gen.CertificateRequestModifier {
	return func(cr *cmapi.CertificateRequest) {
		cr.Generation = generation
	}
}

func requestCondition(conditionType cmapi.CertificateRequestConditionType, status cmmeta.ConditionStatus, reason, message string, transitionTime metav1.Time) cmapi.CertificateRequestCondition {
	return cmapi.CertificateRequestCondition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: &transitionTime,
	}
}

func conflictReasons(plan Plan) []ConflictReason {
	if len(plan.Conflicts) == 0 {
		return nil
	}
	reasons := make([]ConflictReason, 0, len(plan.Conflicts))
	for _, conflict := range plan.Conflicts {
		reasons = append(reasons, conflict.Reason)
	}
	return reasons
}

// applyPlan mirrors what a caller would persist from a plan. It is only used
// to simulate a second reconcile against the previously written status.
func applyPlan(t *testing.T, cr *cmapi.CertificateRequest, plan Plan) {
	t.Helper()
	for _, patch := range plan.ConditionPatches {
		gen.SetCertificateRequestStatusCondition(patch.Condition)(cr)
	}
	if plan.FailureTime != nil {
		cr.Status.FailureTime = plan.FailureTime
	}
}

func TestAggregatorPlan(t *testing.T) {
	baseRequest := func(generation int64, mods ...gen.CertificateRequestModifier) *cmapi.CertificateRequest {
		return gen.CertificateRequest("test-cr",
			append([]gen.CertificateRequestModifier{setGeneration(generation)}, mods...)...,
		)
	}

	tests := map[string]struct {
		request         *cmapi.CertificateRequest
		signal          Signal
		wantNoOp        bool
		wantPatches     []ConditionPatch
		wantFailureTime *metav1.Time
		wantConflicts   []ConflictReason
	}{
		"nil CertificateRequest reports a missing object conflict": {
			request:       nil,
			signal:        Signal{ObservedGeneration: 1},
			wantNoOp:      true,
			wantConflicts: []ConflictReason{ConflictMissingObject},
		},
		"empty signal on a fresh request is a no-op": {
			request:  baseRequest(1),
			signal:   Signal{ObservedGeneration: 1},
			wantNoOp: true,
		},
		"signal computed against an older generation is rejected": {
			request:       baseRequest(2),
			signal:        Signal{ObservedGeneration: 1, Approved: true},
			wantNoOp:      true,
			wantConflicts: []ConflictReason{ConflictStaleGeneration},
		},
		"signal computed against a future generation is rejected": {
			request:       baseRequest(1),
			signal:        Signal{ObservedGeneration: 2, Approved: true},
			wantNoOp:      true,
			wantConflicts: []ConflictReason{ConflictStaleGeneration},
		},
		"approve adds an Approved condition": {
			request: baseRequest(3),
			signal:  Signal{ObservedGeneration: 3, Approved: true},
			wantPatches: []ConditionPatch{{
				Added: true,
				Condition: requestCondition(
					cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue,
					defaultApprovedReason, defaultApprovedMessage, nowMetaTime),
			}},
		},
		"approve honours reason and message overrides": {
			request: baseRequest(1),
			signal: Signal{
				ObservedGeneration: 1,
				Approved:           true,
				ApprovedReason:     "custom-approver",
				ApprovedMessage:    "custom approval message",
			},
			wantPatches: []ConditionPatch{{
				Added: true,
				Condition: requestCondition(
					cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue,
					"custom-approver", "custom approval message", nowMetaTime),
			}},
		},
		"deny adds Denied and Ready conditions and the failure time": {
			request: baseRequest(1),
			signal:  Signal{ObservedGeneration: 1, Denied: true},
			wantPatches: []ConditionPatch{
				{
					Added: true,
					Condition: requestCondition(
						cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue,
						defaultDeniedReason, defaultDeniedMessage, nowMetaTime),
				},
				{
					Added: true,
					Condition: requestCondition(
						cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
						cmapi.CertificateRequestReasonDenied, defaultDeniedMessage, nowMetaTime),
				},
			},
			wantFailureTime: &nowMetaTime,
		},
		"deny honours reason and message overrides": {
			request: baseRequest(1),
			signal: Signal{
				ObservedGeneration: 1,
				Denied:             true,
				DeniedReason:       "policy-agent",
				DeniedMessage:      "forbidden by policy",
			},
			wantPatches: []ConditionPatch{
				{
					Added: true,
					Condition: requestCondition(
						cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue,
						"policy-agent", "forbidden by policy", nowMetaTime),
				},
				{
					Added: true,
					Condition: requestCondition(
						cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
						cmapi.CertificateRequestReasonDenied, "forbidden by policy", nowMetaTime),
				},
			},
			wantFailureTime: &nowMetaTime,
		},
		"fail adds a Failed Ready condition and the failure time": {
			request: baseRequest(1),
			signal: Signal{
				ObservedGeneration: 1,
				Failed:             &Failure{Reason: "SigningError", Message: "issuer refused"},
			},
			wantPatches: []ConditionPatch{{
				Added: true,
				Condition: requestCondition(
					cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
					"SigningError", "issuer refused", nowMetaTime),
			}},
			wantFailureTime: &nowMetaTime,
		},
		"fail with an empty reason defaults to the Failed reason": {
			request: baseRequest(1),
			signal: Signal{
				ObservedGeneration: 1,
				Failed:             &Failure{Message: "boom"},
			},
			wantPatches: []ConditionPatch{{
				Added: true,
				Condition: requestCondition(
					cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
					cmapi.CertificateRequestReasonFailed, "boom", nowMetaTime),
			}},
			wantFailureTime: &nowMetaTime,
		},
		"approval and failure can be aggregated together": {
			request: baseRequest(1),
			signal: Signal{
				ObservedGeneration: 1,
				Approved:           true,
				Failed:             &Failure{Message: "issuer down"},
			},
			wantPatches: []ConditionPatch{
				{
					Added: true,
					Condition: requestCondition(
						cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
						cmapi.CertificateRequestReasonFailed, "issuer down", nowMetaTime),
				},
				{
					Added: true,
					Condition: requestCondition(
						cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue,
						defaultApprovedReason, defaultApprovedMessage, nowMetaTime),
				},
			},
			wantFailureTime: &nowMetaTime,
		},
		"denial takes precedence over failure": {
			request: baseRequest(1),
			signal: Signal{
				ObservedGeneration: 1,
				Denied:             true,
				Failed:             &Failure{Reason: "SigningError", Message: "must not appear"},
			},
			wantPatches: []ConditionPatch{
				{
					Added: true,
					Condition: requestCondition(
						cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue,
						defaultDeniedReason, defaultDeniedMessage, nowMetaTime),
				},
				{
					Added: true,
					Condition: requestCondition(
						cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
						cmapi.CertificateRequestReasonDenied, defaultDeniedMessage, nowMetaTime),
				},
			},
			wantFailureTime: &nowMetaTime,
		},
		"signal asserting both approval and denial is rejected": {
			request:       baseRequest(1),
			signal:        Signal{ObservedGeneration: 1, Approved: true, Denied: true},
			wantNoOp:      true,
			wantConflicts: []ConflictReason{ConflictApprovedAndDenied},
		},
		"object carrying both Approved and Denied is left untouched": {
			request: baseRequest(1,
				gen.SetCertificateRequestStatusCondition(requestCondition(
					cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue,
					defaultApprovedReason, defaultApprovedMessage, oldMetaTime)),
				gen.SetCertificateRequestStatusCondition(requestCondition(
					cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue,
					defaultDeniedReason, defaultDeniedMessage, oldMetaTime)),
			),
			signal:        Signal{ObservedGeneration: 1, Approved: true},
			wantNoOp:      true,
			wantConflicts: []ConflictReason{ConflictApprovedAndDenied},
		},
		"terminal Issued request blocks approval": {
			request: baseRequest(1,
				gen.SetCertificateRequestStatusCondition(requestCondition(
					cmapi.CertificateRequestConditionReady, cmmeta.ConditionTrue,
					cmapi.CertificateRequestReasonIssued, "done", oldMetaTime)),
			),
			signal:        Signal{ObservedGeneration: 1, Approved: true},
			wantNoOp:      true,
			wantConflicts: []ConflictReason{ConflictTerminal},
		},
		"terminal Failed request blocks denial": {
			request: baseRequest(1,
				gen.SetCertificateRequestStatusCondition(requestCondition(
					cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
					cmapi.CertificateRequestReasonFailed, "permanent", oldMetaTime)),
				gen.SetCertificateRequestFailureTime(oldMetaTime),
			),
			signal:   Signal{ObservedGeneration: 1, Denied: true},
			wantNoOp: true,
			wantConflicts: []ConflictReason{
				ConflictTerminal, // adding Denied
				ConflictTerminal, // changing the Ready condition
			},
		},
		"re-asserting identical approval is a no-op and keeps the timestamp": {
			request: baseRequest(1,
				gen.SetCertificateRequestStatusCondition(requestCondition(
					cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue,
					defaultApprovedReason, defaultApprovedMessage, oldMetaTime)),
			),
			signal:   Signal{ObservedGeneration: 1, Approved: true},
			wantNoOp: true,
		},
		"re-asserting identical denial is a no-op and keeps the timestamp": {
			request: baseRequest(1,
				gen.SetCertificateRequestStatusCondition(requestCondition(
					cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue,
					defaultDeniedReason, defaultDeniedMessage, oldMetaTime)),
				gen.SetCertificateRequestStatusCondition(requestCondition(
					cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
					cmapi.CertificateRequestReasonDenied, defaultDeniedMessage, oldMetaTime)),
				gen.SetCertificateRequestFailureTime(oldMetaTime),
			),
			signal:   Signal{ObservedGeneration: 1, Denied: true},
			wantNoOp: true,
		},
		"re-asserting identical failure is a no-op and keeps the timestamp": {
			request: baseRequest(1,
				gen.SetCertificateRequestStatusCondition(requestCondition(
					cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
					cmapi.CertificateRequestReasonFailed, "permanent", oldMetaTime)),
				gen.SetCertificateRequestFailureTime(oldMetaTime),
			),
			signal: Signal{
				ObservedGeneration: 1,
				Failed:             &Failure{Reason: cmapi.CertificateRequestReasonFailed, Message: "permanent"},
			},
			wantNoOp: true,
		},
		"reason and message change preserves the previous timestamp": {
			request: baseRequest(1,
				gen.SetCertificateRequestStatusCondition(requestCondition(
					cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue,
					"old-approver", "old message", oldMetaTime)),
			),
			signal: Signal{
				ObservedGeneration: 1,
				Approved:           true,
				ApprovedReason:     "new-approver",
				ApprovedMessage:    "new message",
			},
			wantPatches: []ConditionPatch{{
				Added: false,
				Condition: requestCondition(
					cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue,
					"new-approver", "new message", oldMetaTime),
			}},
		},
		"status change refreshes the timestamp": {
			request: baseRequest(1,
				gen.SetCertificateRequestStatusCondition(requestCondition(
					cmapi.CertificateRequestConditionReady, cmmeta.ConditionUnknown,
					cmapi.CertificateRequestReasonPending, "in flight", oldMetaTime)),
			),
			signal: Signal{
				ObservedGeneration: 1,
				Failed:             &Failure{Reason: cmapi.CertificateRequestReasonFailed, Message: "gave up"},
			},
			wantPatches: []ConditionPatch{{
				Added: false,
				Condition: requestCondition(
					cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
					cmapi.CertificateRequestReasonFailed, "gave up", nowMetaTime),
			}},
			wantFailureTime: &nowMetaTime,
		},
		"an existing failure time is never rewritten": {
			request: baseRequest(1,
				gen.SetCertificateRequestStatusCondition(requestCondition(
					cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
					cmapi.CertificateRequestReasonPending, "in flight", oldMetaTime)),
				gen.SetCertificateRequestFailureTime(oldMetaTime),
			),
			signal: Signal{
				ObservedGeneration: 1,
				Failed:             &Failure{Message: "gave up"},
			},
			wantPatches: []ConditionPatch{{
				Added: false,
				Condition: requestCondition(
					cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
					cmapi.CertificateRequestReasonFailed, "gave up", oldMetaTime),
			}},
			wantFailureTime: nil,
		},
		"terminal object does not receive a failure time backfill": {
			request: baseRequest(1,
				gen.SetCertificateRequestStatusCondition(requestCondition(
					cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
					cmapi.CertificateRequestReasonFailed, "permanent", oldMetaTime)),
			),
			signal: Signal{
				ObservedGeneration: 1,
				Failed:             &Failure{Reason: cmapi.CertificateRequestReasonFailed, Message: "permanent"},
			},
			wantNoOp: true,
		},
		"pending request can still be approved": {
			request: baseRequest(1,
				gen.SetCertificateRequestStatusCondition(requestCondition(
					cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse,
					cmapi.CertificateRequestReasonPending, "waiting", oldMetaTime)),
			),
			signal: Signal{ObservedGeneration: 1, Approved: true},
			wantPatches: []ConditionPatch{{
				Added: true,
				Condition: requestCondition(
					cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue,
					defaultApprovedReason, defaultApprovedMessage, nowMetaTime),
			}},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			aggregator := NewAggregator(fixedClock)

			plan := aggregator.Plan(test.request, test.signal)

			wantGeneration := int64(0)
			if test.request != nil {
				wantGeneration = test.request.Generation
			}
			if plan.Generation != wantGeneration {
				t.Errorf("expected plan generation %d, got %d", wantGeneration, plan.Generation)
			}
			if plan.NoOp != test.wantNoOp {
				t.Errorf("expected plan NoOp %v, got %v", test.wantNoOp, plan.NoOp)
			}
			if diff := cmp.Diff(test.wantPatches, plan.ConditionPatches); diff != "" {
				t.Errorf("unexpected condition patches (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.wantFailureTime, plan.FailureTime); diff != "" {
				t.Errorf("unexpected failure time (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.wantConflicts, conflictReasons(plan)); diff != "" {
				t.Errorf("unexpected conflict reasons (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPlanIsIdempotentAcrossReconciles(t *testing.T) {
	clock := clocktesting.NewFakeClock(fixedClockStart)
	aggregator := NewAggregator(clock)

	signals := map[string]Signal{
		"approval": {ObservedGeneration: 1, Approved: true},
		"denial":   {ObservedGeneration: 1, Denied: true},
		"failure": {
			ObservedGeneration: 1,
			Failed:             &Failure{Reason: cmapi.CertificateRequestReasonFailed, Message: "nope"},
		},
	}

	for name, signal := range signals {
		t.Run(name, func(t *testing.T) {
			cr := gen.CertificateRequest("test-cr", setGeneration(1))

			first := aggregator.Plan(cr, signal)
			if first.NoOp {
				t.Fatal("expected the first reconcile to produce writes")
			}
			if len(first.Conflicts) != 0 {
				t.Fatalf("expected no conflicts, got %v", first.Conflicts)
			}

			applyPlan(t, cr, first)

			// A later reconcile happens at a different wall-clock time. The
			// re-computed plan must still be a no-op and the persisted
			// timestamps must be exactly those from the first plan.
			clock.Step(time.Hour)
			second := aggregator.Plan(cr, signal)

			if !second.NoOp {
				t.Errorf("expected repeated reconcile to be a no-op, got patches %v", second.ConditionPatches)
			}
			if len(second.Conflicts) != 0 {
				t.Errorf("expected no conflicts on repeated reconcile, got %v", second.Conflicts)
			}
			if second.FailureTime != nil {
				t.Errorf("expected failure time to be left untouched, got %v", second.FailureTime)
			}

			for _, patch := range first.ConditionPatches {
				existing := findCondition(cr, patch.Condition.Type)
				if existing == nil {
					t.Fatalf("condition %s was not applied", patch.Condition.Type)
				}
				if diff := cmp.Diff(patch.Condition.LastTransitionTime, existing.LastTransitionTime); diff != "" {
					t.Errorf("timestamp for %s changed between reconciles (-first +current):\n%s",
						patch.Condition.Type, diff)
				}
			}
		})
	}
}

func TestPlanNeverMutatesInput(t *testing.T) {
	cr := gen.CertificateRequest("test-cr",
		setGeneration(1),
		gen.SetCertificateRequestStatusCondition(requestCondition(
			cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue,
			"old-approver", "old message", oldMetaTime)),
	)
	snapshot := cr.DeepCopy()

	aggregator := NewAggregator(fixedClock)
	plan := aggregator.Plan(cr, Signal{
		ObservedGeneration: 1,
		Approved:           true,
		ApprovedReason:     "new-approver",
		ApprovedMessage:    "new message",
	})
	if plan.NoOp {
		t.Fatal("expected a patch for the changed approval message")
	}

	// Mutating the returned plan must not alias or change the live object.
	if plan.ConditionPatches[0].Condition.LastTransitionTime != nil {
		plan.ConditionPatches[0].Condition.LastTransitionTime.Time = time.Time{}
	}

	if diff := cmp.Diff(snapshot, cr); diff != "" {
		t.Errorf("CertificateRequest was mutated by Plan (-snapshot +actual):\n%s", diff)
	}
}

func TestPlanIsDeterministic(t *testing.T) {
	cr := gen.CertificateRequest("test-cr", setGeneration(1))
	signal := Signal{
		ObservedGeneration: 1,
		Denied:             true,
	}

	clock := clocktesting.NewFakeClock(fixedClockStart)
	aggregator := NewAggregator(clock)

	// Two write plans computed at the same wall-clock time must be identical.
	first := aggregator.Plan(cr, signal)
	second := aggregator.Plan(cr, signal)
	if diff := cmp.Diff(first, second); diff != "" {
		t.Errorf("write plans for identical inputs differ (-first +second):\n%s", diff)
	}

	// Once the plan has been persisted, later reconciles produce identical
	// no-op plans even though the wall clock advances: steady-state plans must
	// never depend on, or refresh, timestamps.
	applyPlan(t, cr, first)
	clock.Step(24 * time.Hour)

	steadyA := aggregator.Plan(cr, signal)
	clock.Step(24 * time.Hour)
	steadyB := aggregator.Plan(cr, signal)

	if !steadyA.NoOp || !steadyB.NoOp {
		t.Fatalf("expected steady-state plans to be no-ops, got %+v and %+v", steadyA, steadyB)
	}
	if diff := cmp.Diff(steadyA, steadyB); diff != "" {
		t.Errorf("steady-state plans differ across reconciles (-first +second):\n%s", diff)
	}
}

func TestNewAggregatorNilClockFallsBackToRealClock(t *testing.T) {
	aggregator := NewAggregator(nil)
	plan := aggregator.Plan(
		gen.CertificateRequest("test-cr", setGeneration(1)),
		Signal{ObservedGeneration: 1, Approved: true},
	)

	if plan.NoOp || len(plan.ConditionPatches) != 1 {
		t.Fatalf("expected a single approval patch, got %+v", plan)
	}
	if plan.ConditionPatches[0].Condition.LastTransitionTime == nil {
		t.Fatal("expected the real clock to populate LastTransitionTime")
	}
}

func TestConflictString(t *testing.T) {
	conflict := Conflict{Reason: ConflictStaleGeneration, Message: "generation mismatch"}
	if got, want := conflict.String(), "StaleGeneration: generation mismatch"; got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func findCondition(cr *cmapi.CertificateRequest, conditionType cmapi.CertificateRequestConditionType) *cmapi.CertificateRequestCondition {
	for i := range cr.Status.Conditions {
		if cr.Status.Conditions[i].Type == conditionType {
			return &cr.Status.Conditions[i]
		}
	}
	return nil
}
