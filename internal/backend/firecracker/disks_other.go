//go:build !linux

package firecracker

import "context"

type diskRef struct {
	Kind   string `json:"kind"`
	Path   string `json:"path,omitempty"`
	ThinID int    `json:"thin_id,omitempty"`
	Bytes  int64  `json:"bytes"`
}

type diskStore struct{ kind string }

func newDiskStore(context.Context, string) (*diskStore, error) { return nil, errLinuxOnly }

func (*diskStore) newGolden(context.Context, string, string, int64) (diskRef, error) {
	return diskRef{}, errLinuxOnly
}
func (*diskStore) attachGolden(diskRef, string, int) error { return errLinuxOnly }
func (*diskStore) seal(context.Context, diskRef) error     { return errLinuxOnly }
func (*diskStore) remove(context.Context, diskRef) error   { return nil }
func (*diskStore) clone(context.Context, diskRef, string, int) (diskRef, error) {
	return diskRef{}, errLinuxOnly
}
func (*diskStore) close(context.Context) error { return nil }
func (*diskStore) snapshotLive(context.Context, diskRef, string, string) (diskRef, error) {
	return diskRef{}, errLinuxOnly
}

func sparsify(string) (int64, error) { return 0, nil }
