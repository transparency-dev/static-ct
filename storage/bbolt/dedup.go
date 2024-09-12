// Copyright 2024 The Tessera authors. All Rights Reserved.
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

// Package bbolt implements modules/dedup using BBolt.
//
// It contains two buckets:
//   - The dedup bucket stores <leafID, idx> pairs. Entries can either be added after sequencing,
//     by the server that received the request, or later when synchronising the dedup storage with
//     the log state.
//   - The size bucket has a single entry: <"size", X>, where X is the largest contiguous index
//     from 0 that has been inserted in the dedup bucket. This allows to know what is the next
//     <leafID, idx> to add to the bucket in order to have a full represation of the log.
//
// Calls to Add<leafID, idx> will update idx to a smaller value, if possible.
package bbolt

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/transparency-dev/static-ct/modules/dedup"

	bolt "go.etcd.io/bbolt"
	"k8s.io/klog/v2"
)

var (
	dedupBucket = "leafIdx"
	sizeBucket  = "logSize"
)

type Storage struct {
	db *bolt.DB
}

// NewStorage returns a new BBolt storage instance with a dedup and size bucket.
//
// The dedup bucket stores <leafID, idx> pairs.
// The size bucket has a single entry: <"size", X>, where X is the largest contiguous index from 0
// that has been inserted in the dedup bucket.
//
// If a database already exists at the provided path, NewStorage will load it.
func NewStorage(path string) (*Storage, error) {
	// TODO(better logging message)
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("bolt.Open(): %v", err)
	}
	s := &Storage{db: db}

	err = db.Update(func(tx *bolt.Tx) error {
		dedupB := tx.Bucket([]byte(dedupBucket))
		sizeB := tx.Bucket([]byte(sizeBucket))
		if dedupB == nil && sizeB == nil {
			klog.V(2).Infof("NewStorage: no pre-existing buckets, will create %q and %q.", dedupBucket, sizeBucket)
			_, err := tx.CreateBucket([]byte(dedupBucket))
			if err != nil {
				return fmt.Errorf("create %q bucket: %v", dedupBucket, err)
			}
			sb, err := tx.CreateBucket([]byte(sizeBucket))
			if err != nil {
				return fmt.Errorf("create %q bucket: %v", sizeBucket, err)
			}
			klog.V(2).Infof("NewStorage: initializing %q with size 0.", sizeBucket)
			err = sb.Put([]byte("size"), itob(0))
			if err != nil {
				return fmt.Errorf("error reading logsize: %v", err)
			}
		} else if dedupB == nil && sizeB != nil {
			return fmt.Errorf("inconsistent deduplication storage state %q is nil but %q it not nil", dedupBucket, sizeBucket)
		} else if dedupB != nil && sizeB == nil {
			return fmt.Errorf("inconsistent deduplication storage state, %q is not nil but %q is nil", dedupBucket, sizeBucket)
		} else {
			klog.V(2).Infof("NewStorage: found pre-existing %q and %q buckets.", dedupBucket, sizeBucket)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error initializing buckets: %v", err)
	}

	return s, nil
}

// Add inserts entries in the dedup bucket and updates the size bucket if need be.
//
// If an entry is already stored under a given key, Add only updates it if the new value is smaller.
// The context is here for consistency with interfaces, but isn't used by BBolt.
func (s *Storage) Add(_ context.Context, lidxs []dedup.LeafIdx) error {
	for _, lidx := range lidxs {
		err := s.db.Update(func(tx *bolt.Tx) error {
			db := tx.Bucket([]byte(dedupBucket))
			sb := tx.Bucket([]byte(sizeBucket))
			sizeB := sb.Get([]byte("size"))
			if sizeB == nil {
				return fmt.Errorf("can't find log size in bucket %q", sizeBucket)
			}
			size := btoi(sizeB)

			if old := db.Get(lidx.LeafID); old != nil && btoi(old) <= lidx.Idx {
				klog.V(3).Infof("Add(): bucket %q already contains a smaller index %d < %d for entry %q, not updating", dedupBucket, btoi(old), lidx.Idx, hex.EncodeToString(lidx.LeafID))
			} else if err := db.Put(lidx.LeafID, itob(lidx.Idx)); err != nil {
				return err
			}
			// size is a length, lidx.I an index, so if they're equal,
			// lidx is a new entry.
			if size == lidx.Idx {
				klog.V(3).Infof("Add(): updating deduped size to %d", size+1)
				if err := sb.Put([]byte("size"), itob(size+1)); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("b.Put(): error writing leaf index %d: err", lidx.Idx)
		}
	}
	return nil
}

// Get reads entries from the dedup bucket.
//
// If the requested entry is missing from the bucket, returns false ("comma ok" idiom).
// The context is here for consistency with interfaces, but isn't used by BBolt.
func (s *Storage) Get(_ context.Context, leafID []byte) (uint64, bool, error) {
	var idx []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dedupBucket))
		v := b.Get(leafID)
		if v != nil {
			idx = make([]byte, 8)
			copy(idx, v)
		}
		return nil
	})
	if idx == nil {
		return 0, false, nil
	}
	return btoi(idx), true, nil
}

// LogSize reads the latest entry from the size bucket.
func (s *Storage) LogSize() (uint64, error) {
	var size []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sizeBucket))
		v := b.Get([]byte("size"))
		if v != nil {
			size = make([]byte, 8)
			copy(size, v)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("error reading from %q: %v", sizeBucket, err)
	}
	if size == nil {
		return 0, fmt.Errorf("can't find log size in bucket %q", sizeBucket)
	}
	return btoi(size), nil
}

// itob returns an 8-byte big endian representation of idx.
func itob(idx uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, idx)
}

// btoi converts a byte array to a uint64
func btoi(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}
