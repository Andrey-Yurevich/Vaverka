//go:build amd64 && linux

package constants

// SendMmsgSyscallIndex https://github.com/torvalds/linux/blob/ffd294d346d185b70e28b1a28abe367bbfe53c04/arch/x86/entry/syscalls/syscall_64.tbl#L319
const SendMmsgSyscallIndex = 307
