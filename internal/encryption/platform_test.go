package encryption

import "runtime"

func isLinux() bool {
	return runtime.GOOS == "linux"
}
