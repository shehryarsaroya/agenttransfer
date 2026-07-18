package cli

import (
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// safeImplicitDownloadName converts an untrusted manifest/header filename to
// one ordinary, visible basename in the current directory. Explicit -o paths
// remain under the caller's control and do not pass through this function.
func safeImplicitDownloadName(raw string) string {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	name := pathpkg.Base(raw)
	if name == "" || name == "." || name == ".." || name == "/" {
		return "download.bin"
	}

	var b strings.Builder
	for _, r := range name {
		switch {
		case !unicode.IsGraphic(r), strings.ContainsRune(`<>:"/\|?*`, r):
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	name = strings.TrimSpace(strings.TrimRight(b.String(), ". "))
	if name == "" || name == "." || name == ".." {
		return "download.bin"
	}
	// Hidden names can overwrite security-sensitive dotfiles in the working
	// directory. Keep the recognizable suffix without making it hidden.
	if strings.HasPrefix(name, ".") {
		name = "download" + name
	}
	// Windows device names remain special even with an extension.
	stem := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" ||
		(strings.HasPrefix(stem, "COM") && len(stem) == 4 && stem[3] >= '1' && stem[3] <= '9') ||
		(strings.HasPrefix(stem, "LPT") && len(stem) == 4 && stem[3] >= '1' && stem[3] <= '9') {
		name = "_" + name
	}
	// Leave headroom for the temporary-file prefix and common filesystem
	// limits. Trim only at UTF-8 boundaries.
	for len(name) > 200 {
		_, n := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-n]
	}
	if name == "" {
		return "download.bin"
	}
	return name
}

// commitDownloadedFile installs a fully verified temp file. Implicit names
// are constrained to the current directory and linked with O_EXCL semantics,
// so a remote filename can never overwrite an existing local file. Explicit
// output paths retain the CLI's historical overwrite behavior.
func commitDownloadedFile(tmpName, dest string, explicit bool) error {
	if explicit {
		return os.Rename(tmpName, dest)
	}
	if filepath.IsAbs(dest) || filepath.Dir(dest) != "." || filepath.Base(dest) != dest || dest == "." || dest == ".." {
		return fmt.Errorf("refusing unsafe implicit download destination %q", dest)
	}
	if err := os.Link(tmpName, dest); err != nil {
		if _, statErr := os.Lstat(dest); statErr == nil {
			return fmt.Errorf("refusing to overwrite existing implicit download destination %q; choose an explicit path with -o", dest)
		}
		return fmt.Errorf("install implicit download %q without overwriting: %w", dest, err)
	}
	if err := os.Remove(tmpName); err != nil {
		return fmt.Errorf("download saved as %q but temporary cleanup failed: %w", dest, err)
	}
	return nil
}
