// Copyright 2017 Google LLC. All Rights Reserved.
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
	"encoding/hex"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"k8s.io/klog/v2"
)

const vLevel = 9

// requestLog allows implementations to do structured logging of CTFE
// request parameters, submitted chains and other internal details that
// are useful for log operators when debugging issues. CTFE handlers will
// call the appropriate methods during request processing. The implementation
// is responsible for collating and storing the resulting logging information.
type requestLog interface {
	// start will be called once at the beginning of handling each request.
	// The supplied context will be the one used for request processing and
	// can be used by the logger to set values on the returned context.
	// The returned context should be used in all the following calls to
	// this API. This is normally arranged by the request handler code.
	start(context.Context) context.Context
	// origin will be called once per request to set the log prefix.
	origin(context.Context, string)
	// addDERToChain will be called once for each certificate in a submitted
	// chain. It's called early in request processing so the supplied bytes
	// have not been checked for validity. Calls will be in order of the
	// certificates as presented in the request with the root last.
	addDERToChain(context.Context, []byte)
	// addCertToChain will be called once for each certificate in the chain
	// after it has been parsed and verified. Calls will be in order of the
	// certificates as presented in the request with the root last.
	addCertToChain(context.Context, *x509.Certificate)
	// issueSCT will be called once when the server is about to issue an SCT to a
	// client. This should not be called if the submission process fails before an
	// SCT could be presented to a client, even if this is unrelated to
	// the validity of the submitted chain. The SCT bytes will be in TLS
	// serialized format.
	issueSCT(context.Context, []byte)
	// status will be called once to set the HTTP status code that was the
	// the result after the request has been handled.
	status(context.Context, int)
}

// DefaultRequestLog is an implementation of RequestLog that does nothing
// except log the calls at a high level of verbosity.
type DefaultRequestLog struct {
}

// start logs the start of request processing.
func (dlr *DefaultRequestLog) start(ctx context.Context) context.Context {
	klog.V(vLevel).Info("RL: Start")
	return ctx
}

// origin logs the origin of the CT log that this request is for.
func (dlr *DefaultRequestLog) origin(_ context.Context, p string) {
	klog.V(vLevel).Infof("RL: LogOrigin: %s", p)
}

// addDERToChain logs the raw bytes of a submitted certificate.
func (dlr *DefaultRequestLog) addDERToChain(_ context.Context, d []byte) {
	// Explicit hex encoding below to satisfy CodeQL:
	klog.V(vLevel).Infof("RL: Cert DER: %s", hex.EncodeToString(d))
}

// addCertToChain logs some issuer / subject / timing fields from a
// certificate that is part of a submitted chain.
func (dlr *DefaultRequestLog) addCertToChain(_ context.Context, cert *x509.Certificate) {
	klog.V(vLevel).Infof("RL: Cert: Sub: %s Iss: %s notBef: %s notAft: %s",
		x509util.NameToString(cert.Subject),
		x509util.NameToString(cert.Issuer),
		cert.NotBefore.Format(time.RFC1123Z),
		cert.NotAfter.Format(time.RFC1123Z))
}

// issueSCT logs an SCT that will be issued to a client.
func (dlr *DefaultRequestLog) issueSCT(_ context.Context, sct []byte) {
	klog.V(vLevel).Infof("RL: Issuing SCT: %x", sct)
}

// status logs the response HTTP status code after processing completes.
func (dlr *DefaultRequestLog) status(_ context.Context, s int) {
	klog.V(vLevel).Infof("RL: Status: %d", s)
}
