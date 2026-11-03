//go:build windows

package fsx

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Quant-Off/pairier/host/internal/winsys"
)

const ExeSuffix = ".exe"

func lstatRegular(path string) (fs.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return nil, fmt.Errorf("%w: %s is a symlink or reparse point", ErrInsecure, path)
	}
	return fi, nil
}

func wrap(err error) error {
	if errors.Is(err, winsys.ErrInsecure) {
		return fmt.Errorf("%w: %v", ErrInsecure, err)
	}
	return err
}

func CheckPrivateDir(path string) error {
	fi, err := lstatRegular(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrInsecure, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	remote, err := winsys.IsRemotePath(abs)
	if err != nil {
		return err
	}
	if remote {
		return fmt.Errorf("%w: %s is on a network drive", ErrInsecure, path)
	}
	return wrap(winsys.CheckPath(path, winsys.Policy{}))
}

func CheckPrivateFile(path string) error {
	fi, err := lstatRegular(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrInsecure, path)
	}
	return wrap(winsys.CheckPath(path, winsys.Policy{}))
}

func CheckNotWritableByOthers(path string) error {
	fi, err := lstatRegular(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrInsecure, path)
	}
	return wrap(winsys.CheckPath(path, winsys.Policy{AllowAdministrators: true}))
}

func MkdirPrivate(path string) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa, free, err := winsys.PrivateAttributes("dir")
	if err != nil {
		return err
	}
	defer free()
	if err := syscall.CreateDirectory(name, sa); err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	return nil
}

func MakePrivate(path string) error {
	return winsys.SetPrivate(path, "dir")
}

func OpenNoFollow(path string, flag int, perm fs.FileMode) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return nil, fmt.Errorf("%w: %s is a symlink or reparse point", ErrInsecure, path)
	}
	return os.OpenFile(path, flag, perm)
}

func Lock(f *os.File) error {
	return winsys.Lock(syscall.Handle(f.Fd()))
}

func Unlock(f *os.File) error {
	return winsys.Unlock(syscall.Handle(f.Fd()))
}

func SyncDir(string) error {
	return nil
}

func Rename(oldpath, newpath string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		err = os.Rename(oldpath, newpath)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.Errno(32)) && !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return err
}

func IsExecutable(fi fs.FileInfo, path string) bool {
	return fi.Mode().IsRegular() && strings.EqualFold(filepath.Ext(path), ExeSuffix)
}
