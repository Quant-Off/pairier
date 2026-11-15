//go:build windows

package console

import "github.com/Quant-Off/pairier/host/internal/winsys"

func systemKorean() bool { return winsys.UserUILanguage()&0x3ff == 0x12 }
