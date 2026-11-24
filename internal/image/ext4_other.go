//go:build !linux

package image

import (
	"context"
	"errors"
)

// Ext4 needs Linux (mkfs.ext4).
func (s *Store) Ext4(context.Context, Image) (string, error) {
	return "", errors.New("ext4 images need Linux")
}
