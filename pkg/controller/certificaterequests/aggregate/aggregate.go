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

// Package aggregate contains a pure, idempotent aggregator that turns a
// CertificateRequest's observed generation together with its approval, denial
// and failure signals into a stable status transition plan.
//
// The aggregator never performs any I/O and in particular never calls the
// Kubernetes API: it only returns the fields the caller should write and the
// conflicts that prevent a transition. Persisting the returned plan is the
// caller's responsibility.
package aggregate

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

const (
	defaultApprovedReason  = "cert-manager.io"
	defaultApprovedMessage = "Certificate request has been approved by cert-manager.io"

	defaultDeniedReason  = "cert-manager.io"
	defaultDeniedMessage = "The CertificateRequest was denied by an approval controller"
)

// ConflictReason is a machine-readable explanation of why a desired transition
// cannot be written to a CertificateRequest.
type ConflictReason string

const (
	// ConflictMissingObject means the aggregator was called without a live
	// CertificateRequest to aggregate against.
	ConflictMissingObject ConflictReason = "MissingObject"

	// ConflictStaleGeneration means the signal was computed against a different
	// generation than the live CertificateRequest. A result computed against an
	// older generation must never overwrite a newer object, and a signal
	// targeting a future generation cannot be trusted either.
	ConflictStaleGeneration ConflictReason = "StaleGeneration"

	// ConflictApprovedAndDenied means approval and denial are asserted at the
	// same time, either by the signal or by the conditions already stored on
	// the object. The two conditions are mutually exclusive by API contract.
	ConflictApprovedAndDenied ConflictReason = "ApprovedAndDenied"

	// ConflictTerminal means the CertificateRequest is already in a terminal
	// state (denied, failed or issued) and the requested transition would change
	// one of its frozen conditions.
	ConflictTerminal ConflictReason = "Terminal"
)

// Conflict describes a single rejected transition.
type Conflict struct {
	// Reason is the machine-readable conflict category.
	Reason ConflictReason
	// Message is a human-readable description of the conflict.
	Message string
}

// String returns a deterministic "Reason: Message" representation.
func (c Conflict) String() string {
	return fmt.Sprintf("%s: %s", c.Reason, c.Message)
}

// Signal describes the approval state that a single reconcile iteration wants
// to reach. It is a plain value and never performs any I/O.
//
// The zero value asserts nothing and always yields an idempotent no-op plan.
type Signal struct {
	// ObservedGeneration is metadata.generation of the CertificateRequest that
	// this signal was computed against. A signal whose ObservedGeneration does
	// not match the live object's generation is never applied.
	ObservedGeneration int64

	// Approved requests the Approved condition to become True.
	Approved bool
	// ApprovedReason and ApprovedMessage optionally override the defaults used
	// when populating the Approved condition.
	ApprovedReason  string
	ApprovedMessage string

	// Denied requests the Denied condition to become True and, together with it,
	// a Ready condition with status False and reason Denied. Denial takes
	// precedence over Failed when both are set, since a denied request can
	// never be signed.
	Denied bool
	// DeniedReason and DeniedMessage optionally override the defaults used when
	// populating the Denied and Ready conditions.
	DeniedReason  string
	DeniedMessage string

	// Failed, when non-nil, requests a Ready condition with status False and
	// reason Failed together with status.failureTime.
	Failed *Failure
}

// Failure carries the reason and message of a signing failure.
type Failure struct {
	// Reason defaults to cmapi.CertificateRequestReasonFailed when empty.
	Reason string
	// Message is the human-readable failure detail.
	Message string
}

// ConditionPatch is a single, fully resolved condition upsert that the caller
// should persist. The LastTransitionTime is already resolved: the caller must
// not recompute it.
type ConditionPatch struct {
	// Condition is the complete condition value to write, including the exact
	// LastTransitionTime that must be persisted.
	Condition cmapi.CertificateRequestCondition
	// Added reports that the condition does not yet exist on the live
	// CertificateRequest.
	Added bool
}

// Plan is the stable transition plan computed for one CertificateRequest and
// one Signal. It contains no live clients and can be inspected or discarded
// without side effects.
type Plan struct {
	// Generation is the live object generation this plan was computed for.
	Generation int64

	// NoOp is true when the signal requires no field to be written. A plan that
	// reports conflicts is always a no-op. Repeated reconciles therefore keep
	// producing no-op plans and never refresh timestamps.
	NoOp bool

	// ConditionPatches is the deterministic, ordered list of condition upserts
	// to write. It is empty when no condition needs changing.
	ConditionPatches []ConditionPatch

	// FailureTime is the value to write to status.failureTime. It is nil when
	// the field must be left untouched, and in particular when failureTime is
	// already set on the live object.
	FailureTime *metav1.Time

	// Conflicts lists the transitions that were rejected. It is empty when the
	// full signal can be applied.
	Conflicts []Conflict
}

// Aggregator computes idempotent CertificateRequest status transition plans.
// It holds no Kubernetes client and never calls the API.
type Aggregator struct {
	clock clock.Clock
}

// NewAggregator returns an Aggregator using the given clock to resolve
// LastTransitionTime and failureTime values. A nil clock falls back to the
// real wall clock.
func NewAggregator(c clock.Clock) *Aggregator {
	if c == nil {
		c = clock.RealClock{}
	}
	return &Aggregator{clock: c}
}

// Plan computes the transition plan for cr from signal. It never mutates cr
// and never performs I/O. The result is deterministic: identical inputs
// produce identical plans, and a signal that already matches the live object
// yields a no-op without touching any timestamp.
func (a *Aggregator) Plan(cr *cmapi.CertificateRequest, signal Signal) Plan {
	if cr == nil {
		return Plan{
			NoOp: true,
			Conflicts: []Conflict{{
				Reason:  ConflictMissingObject,
				Message: "cannot aggregate a nil CertificateRequest",
			}},
		}
	}

	plan := Plan{Generation: cr.Generation}

	// A result computed for another generation must never be written to the
	// live object: an older result would overwrite a newer object, and a signal
	// from a future generation cannot be trusted against the current object.
	if signal.ObservedGeneration != cr.Generation {
		plan.NoOp = true
		plan.Conflicts = append(plan.Conflicts, Conflict{
			Reason: ConflictStaleGeneration,
			Message: fmt.Sprintf(
				"signal observed generation %d does not match CertificateRequest generation %d",
				signal.ObservedGeneration, cr.Generation),
		})
		return plan
	}

	// Approved and Denied are mutually exclusive by API contract. An object
	// carrying both is invalid and must not be mutated until it is repaired.
	if apiutil.CertificateRequestIsApproved(cr) && apiutil.CertificateRequestIsDenied(cr) {
		plan.NoOp = true
		plan.Conflicts = append(plan.Conflicts, Conflict{
			Reason:  ConflictApprovedAndDenied,
			Message: "CertificateRequest carries both an Approved and a Denied condition",
		})
		return plan
	}

	// A single signal must not assert both outcomes either.
	if signal.Approved && signal.Denied {
		plan.NoOp = true
		plan.Conflicts = append(plan.Conflicts, Conflict{
			Reason:  ConflictApprovedAndDenied,
			Message: "signal asserts both approval and denial",
		})
		return plan
	}

	terminal := isTerminal(cr)
	now := metav1.NewTime(a.clock.Now())

	// Resolve every desired condition in a fixed order so the plan is stable
	// across repeated reconciles.
	for _, desired := range desiredConditions(signal) {
		patch, conflict := resolveCondition(cr, desired, terminal, now)
		if conflict != nil {
			plan.Conflicts = append(plan.Conflicts, *conflict)
			continue
		}
		if patch != nil {
			plan.ConditionPatches = append(plan.ConditionPatches, *patch)
		}
	}

	// failureTime accompanies a terminal denial or failure, but only once: an
	// already set failureTime is preserved and repeated reconciles never rewrite
	// it. A terminal object is frozen and never receives a backfill either.
	if (signal.Denied || signal.Failed != nil) && cr.Status.FailureTime == nil && !terminal {
		plan.FailureTime = &now
	}

	plan.NoOp = len(plan.ConditionPatches) == 0 && plan.FailureTime == nil
	return plan
}

// isTerminal reports whether cr has already reached a state that must not be
// modified: a Denied condition, or a Ready condition with reason Failed or
// Issued.
func isTerminal(cr *cmapi.CertificateRequest) bool {
	if apiutil.CertificateRequestIsDenied(cr) {
		return true
	}

	switch apiutil.CertificateRequestReadyReason(cr) {
	case cmapi.CertificateRequestReasonFailed, cmapi.CertificateRequestReasonIssued:
		return true
	}

	return false
}

// desiredConditions converts the signal into the ordered, fully specified
// conditions it wants the object to carry. Timestamps are intentionally left
// unset and resolved later against the live object.
func desiredConditions(signal Signal) []cmapi.CertificateRequestCondition {
	var desired []cmapi.CertificateRequestCondition

	// Denial takes precedence over failure: a denied request can never be
	// signed, so an accompanying failure signal is irrelevant.
	if signal.Denied {
		reason := signal.DeniedReason
		if reason == "" {
			reason = defaultDeniedReason
		}
		message := signal.DeniedMessage
		if message == "" {
			message = defaultDeniedMessage
		}

		return []cmapi.CertificateRequestCondition{
			{
				Type:    cmapi.CertificateRequestConditionDenied,
				Status:  cmmeta.ConditionTrue,
				Reason:  reason,
				Message: message,
			},
			{
				Type:    cmapi.CertificateRequestConditionReady,
				Status:  cmmeta.ConditionFalse,
				Reason:  cmapi.CertificateRequestReasonDenied,
				Message: message,
			},
		}
	}

	// Approval and failure can coexist (a request may be approved before the
	// signing attempt fails), so both conditions are emitted when requested.
	if signal.Failed != nil {
		reason := signal.Failed.Reason
		if reason == "" {
			reason = cmapi.CertificateRequestReasonFailed
		}
		desired = append(desired, cmapi.CertificateRequestCondition{
			Type:    cmapi.CertificateRequestConditionReady,
			Status:  cmmeta.ConditionFalse,
			Reason:  reason,
			Message: signal.Failed.Message,
		})
	}

	if signal.Approved {
		reason := signal.ApprovedReason
		if reason == "" {
			reason = defaultApprovedReason
		}
		message := signal.ApprovedMessage
		if message == "" {
			message = defaultApprovedMessage
		}
		desired = append(desired, cmapi.CertificateRequestCondition{
			Type:    cmapi.CertificateRequestConditionApproved,
			Status:  cmmeta.ConditionTrue,
			Reason:  reason,
			Message: message,
		})
	}

	return desired
}

// resolveCondition compares one desired condition against the live object and
// returns either the patch to write, a conflict that blocks it, or (nil, nil)
// when the live object already matches and no timestamp must be touched.
func resolveCondition(cr *cmapi.CertificateRequest, desired cmapi.CertificateRequestCondition, terminal bool, now metav1.Time) (*ConditionPatch, *Conflict) {
	existing := apiutil.GetCertificateRequestCondition(cr, desired.Type)

	if existing == nil {
		if terminal {
			return nil, &Conflict{
				Reason: ConflictTerminal,
				Message: fmt.Sprintf(
					"refusing to add %s condition: CertificateRequest is already in a terminal state",
					desired.Type),
			}
		}

		desired.LastTransitionTime = &now
		return &ConditionPatch{Condition: desired, Added: true}, nil
	}

	// Same status, reason and message means the condition already reflects the
	// signal: nothing is written and the existing LastTransitionTime is
	// preserved, so repeated reconciles never refresh timestamps.
	if existing.Status == desired.Status &&
		existing.Reason == desired.Reason &&
		existing.Message == desired.Message {
		return nil, nil
	}

	if terminal {
		return nil, &Conflict{
			Reason: ConflictTerminal,
			Message: fmt.Sprintf(
				"refusing to change terminal %s condition", desired.Type),
		}
	}

	// A reason/message-only update keeps the previous LastTransitionTime; only
	// an actual status transition receives a fresh timestamp. The pointer is
	// copied so the plan never aliases the live object's metadata.
	desired.LastTransitionTime = existing.LastTransitionTime.DeepCopy()
	if existing.Status != desired.Status {
		desired.LastTransitionTime = &now
	}

	return &ConditionPatch{Condition: desired, Added: false}, nil
}
