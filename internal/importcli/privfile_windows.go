//go:build windows

package importcli

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// privateSDDL returns a protected DACL (no inherited entries) that gives full
// access to the current user and to SYSTEM, and nothing to anyone else: the
// Windows form of mode 0600. Administrators can still take ownership, as
// they can of any file.
func privateSDDL() (string, error) {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read the current user: %w", err)
	}
	return "D:P(A;;FA;;;" + u.User.Sid.String() + ")(A;;FA;;;SY)", nil
}

// createPrivate creates or truncates a file only its owner can read. A new
// file is created with the private DACL (no window with the folder's
// inherited one); an existing file gets the private DACL before it is
// truncated and written.
func createPrivate(path string) (*os.File, error) {
	sddl, err := privateSDDL()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		dacl, _, err := sd.DACL()
		if err != nil {
			return nil, err
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, dacl, nil); err != nil {
			return nil, fmt.Errorf("restrict %s to its owner: %w", path, err)
		}
		return os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- the user names the file
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
