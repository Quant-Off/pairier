//go:build unix

package fsx

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

const ExeSuffix = ""

func lstatRegular(path string) (fs.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s is a symlink", ErrInsecure, path)
	}
	return fi, nil
}

func owned(fi fs.FileInfo, path string) error {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%w: %s is not owned by the current user", ErrInsecure, path)
	}
	return nil
}

func CheckPrivateDir(path string) error {
	fi, err := lstatRegular(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrInsecure, path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s is accessible by group or others", ErrInsecure, path)
	}
	return owned(fi, path)
}

func CheckPrivateFile(path string) error {
	fi, err := lstatRegular(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrInsecure, path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s is accessible by group or others", ErrInsecure, path)
	}
	return nil
}

func CheckNotWritableByOthers(path string) error {
	fi, err := lstatRegular(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrInsecure, path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by group or others", ErrInsecure, path)
	}
	return nil
}

func MkdirPrivate(path string) error {
	return os.Mkdir(path, 0o700)
}

func MakePrivate(path string) error {
	return os.Chmod(path, 0o700)
}

func OpenNoFollow(path string, flag int, perm fs.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag|syscall.O_NOFOLLOW, perm)
}

func Lock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func Unlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

func SyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func Rename(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}

func IsExecutable(fi fs.FileInfo, _ string) bool {
	return fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}
