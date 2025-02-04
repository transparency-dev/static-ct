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

package x509util

import (
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// TODO(phboneff): inline / delete this
// ReadPossiblePEMFile loads data from a file which may be in DER format
// or may be in PEM format (with the given blockname).
func ReadPossiblePEMFile(filename, blockname string) ([][]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to read data: %v", filename, err)
	}
	return dePEM(data, blockname), nil
}

func dePEM(data []byte, blockname string) [][]byte {
	var results [][]byte
	if strings.Contains(string(data), "BEGIN "+blockname) {
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == blockname {
				results = append(results, block.Bytes)
			}
		}
	} else {
		results = append(results, data)
	}
	return results
}
