// Copyright 2016 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sctfe

import (
	"context"
	"time"

	"github.com/google/trillian/monitoring"
)

// InstanceOptions describes the options for a log instance.
type InstanceOptions struct {
	// Validated holds the original configuration options for the log, and some
	// of its fields parsed as a result of validating it.
	Validated *ValidatedLogConfig
	// Storage stores data to implement https://c2sp.org/static-ct-api.
	Storage *CTStorage
	// Deadline is a timeout for HTTP requests.
	Deadline time.Duration
	// MetricFactory allows creating metrics.
	MetricFactory monitoring.MetricFactory
	// RequestLog provides structured logging of CTFE requests.
	RequestLog         RequestLog
	MaskInternalErrors bool
	TimeSource         TimeSource
}

// Instance is a set up log/mirror instance. It must be created with the
// SetUpInstance call.
type Instance struct {
	Handlers PathHandlers
}

// SetUpInstance sets up a log (or log mirror) instance using the provided
// configuration, and returns an object containing a set of handlers for this
// log, and an STH getter.
func SetUpInstance(ctx context.Context, opts InstanceOptions) (*Instance, error) {
	cfg := opts.Validated

	logInfo := newLogInfo(opts, cfg.CertValidationOpts, cfg.Signer, opts.TimeSource, opts.Storage)

	handlers := logInfo.Handlers(opts.Validated.Origin)
	return &Instance{Handlers: handlers}, nil
}
