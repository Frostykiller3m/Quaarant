package cli

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
	"github.com/Frostykiller3m/Quaarant/internal/safetar"
)

// A sandbox location is ID:/abs/path. Ids are at least 2 characters, so a Windows drive
// letter ("c:/x") is never mistaken for one.
var sandboxLocRe = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{1,62}):(/.*)$`)

type location struct {
	sandbox string // empty for local
	path    string // local path, "-" for stdin/stdout, or in-sandbox absolute path
}

func parseLocation(s string) location {
	if m := sandboxLocRe.FindStringSubmatch(s); m != nil {
		return location{sandbox: m[1], path: path.Clean(m[2])}
	}
	return location{path: s}
}

func newCpCommand(g *globals) *cobra.Command {
	var quiet bool
	cmd := &cobra.Command{
		Use:   "cp SRC DST",
		Short: "Copy files between the host and a sandbox",
		Long: "cp copies a file or directory into or out of a sandbox. One side is SANDBOX:/path.\n\n" +
			"Into a sandbox, SRC is placed inside the directory DST (created if missing) and owned by\n" +
			"the sandbox user. Out of a sandbox, SRC is placed inside the local directory DST. Use - for\n" +
			"a tar archive on stdin (SRC) or stdout (DST). Files coming out are untrusted: they are\n" +
			"unpacked without setuid bits or device nodes and can never land outside DST.",
		Example: "  qt cp ./repo 3f2a9c1b7e04:/work        # -> /work/repo\n" +
			"  qt cp 3f2a9c1b7e04:/tmp/out ./results    # -> ./results/out\n" +
			"  qt cp 3f2a9c1b7e04:/work - > work.tar",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, dst := parseLocation(args[0]), parseLocation(args[1])
			switch {
			case src.sandbox == "" && dst.sandbox != "":
				return copyIn(cmd, g, src, dst, quiet)
			case src.sandbox != "" && dst.sandbox == "":
				return copyOut(cmd, g, src, dst, quiet)
			default:
				return errors.New("exactly one of SRC and DST must be SANDBOX:/path")
			}
		},
	}
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "do not print a summary")
	return cmd
}

func copyIn(cmd *cobra.Command, g *globals, src, dst location, quiet bool) error {
	var tarStream io.Reader
	if src.path == "-" {
		tarStream = cmd.InOrStdin()
	} else {
		if _, err := os.Lstat(src.path); err != nil {
			return fmt.Errorf("copy %s: %w", src.path, err)
		}
		pr, pw := io.Pipe()
		go func() { _ = pw.CloseWithError(writeLocalTar(src.path, pw)) }()
		defer func() { _ = pr.Close() }()
		tarStream = pr
	}
	c, closer, err := g.client()
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	stream, err := c.CopyIn(cmd.Context())
	if err != nil {
		return friendly(err, g.socket)
	}
	if err := stream.Send(&qtdv1.CopyInRequest{Msg: &qtdv1.CopyInRequest_Header_{Header: &qtdv1.CopyInRequest_Header{SandboxId: dst.sandbox, Dir: dst.path}}}); err != nil {
		return friendly(err, g.socket)
	}
	buf := make([]byte, 256<<10)
	for {
		n, rerr := tarStream.Read(buf)
		if n > 0 {
			if err := stream.Send(&qtdv1.CopyInRequest{Msg: &qtdv1.CopyInRequest_TarChunk{TarChunk: append([]byte(nil), buf[:n]...)}}); err != nil {
				break // the server ended the stream; CloseAndRecv reports why
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return fmt.Errorf("read %s: %w", src.path, rerr)
		}
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return friendly(err, g.socket)
	}
	if !quiet {
		fmt.Fprintf(cmd.ErrOrStderr(), "qt: copied %d entries (%s archive) into %s:%s\n", resp.GetFiles(), humanBytes(resp.GetBytes()), dst.sandbox, dst.path)
	}
	return nil
}

func copyOut(cmd *cobra.Command, g *globals, src, dst location, quiet bool) error {
	c, closer, err := g.client()
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	stream, err := c.CopyOut(cmd.Context(), &qtdv1.CopyOutRequest{SandboxId: src.sandbox, Path: src.path})
	if err != nil {
		return friendly(err, g.socket)
	}
	pr, pw := io.Pipe()
	go func() {
		for {
			msg, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				_ = pw.Close()
				return
			}
			if err != nil {
				_ = pw.CloseWithError(friendly(err, g.socket))
				return
			}
			if _, err := pw.Write(msg.GetTarChunk()); err != nil {
				return
			}
		}
	}()
	defer func() { _ = pr.Close() }()
	if dst.path == "-" {
		n, err := io.Copy(cmd.OutOrStdout(), pr)
		if err != nil {
			return err
		}
		if !quiet {
			fmt.Fprintf(cmd.ErrOrStderr(), "qt: wrote a %s tar of %s:%s\n", humanBytes(uint64(n)), src.sandbox, src.path) //nolint:gosec // G115: n >= 0
		}
		return nil
	}
	if err := os.MkdirAll(dst.path, 0o755); err != nil { //nolint:gosec // G301: a normal user directory
		return fmt.Errorf("create %s: %w", dst.path, err)
	}
	st, err := safetar.Unpack(pr, dst.path, safetar.DefaultUnpackLimits, false)
	if err != nil {
		return fmt.Errorf("unpack into %s: %w", dst.path, err)
	}
	if !quiet {
		fmt.Fprintf(cmd.ErrOrStderr(), "qt: copied %d files, %d dirs, %d links (%s) to %s",
			st.Files, st.Dirs, st.Symlinks+st.Hardlinks, humanBytes(uint64(st.Bytes)), dst.path) //nolint:gosec // G115: Bytes >= 0
		if st.Skipped > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "; skipped %d special files", st.Skipped)
		}
		fmt.Fprintln(cmd.ErrOrStderr())
	}
	return nil
}

// writeLocalTar archives a local file or directory; entries are named base(src)/...
// Symlinks are stored as links; fifos, sockets and devices are skipped.
func writeLocalTar(src string, w io.Writer) error {
	tw := tar.NewWriter(w)
	base := filepath.Base(filepath.Clean(src))
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if fi.Mode()&(fs.ModeNamedPipe|fs.ModeSocket|fs.ModeDevice|fs.ModeIrregular) != 0 {
			return nil
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		name := path.Join(base, filepath.ToSlash(rel))
		link := ""
		if fi.Mode()&fs.ModeSymlink != 0 {
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		}
		hdr, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			return err
		}
		hdr.Name, hdr.Uname, hdr.Gname, hdr.Format = name, "", "", tar.FormatPAX
		if fi.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			f, err := os.Open(p) //nolint:gosec // G304: the user's own file, named on the command line
			if err != nil {
				return err
			}
			_, err = io.CopyN(tw, f, hdr.Size)
			_ = f.Close()
			if err != nil {
				return fmt.Errorf("%s changed while copying: %w", p, err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

func newDiffCommand(g *globals) *cobra.Command {
	var asJSON, noTrunc bool
	cmd := &cobra.Command{
		Use:   "diff SANDBOX [OTHER]",
		Short: "List files a sandbox added, changed or deleted, with sizes and hashes",
		Long: "diff compares a sandbox's writable layer with its image. KIND is A (added), M (modified)\n" +
			"or D (deleted). With OTHER, it compares two running sandboxes (vm): files in SANDBOX\n" +
			"relative to OTHER, then what each one did that the other did not. Paths come from the\n" +
			"sandbox and are quoted when they hold control characters or invalid UTF-8.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, closer, err := g.client()
			if err != nil {
				return err
			}
			defer func() { _ = closer.Close() }()
			req := &qtdv1.DiffRequest{SandboxId: args[0]}
			if len(args) == 2 {
				req.AgainstSandboxId = args[1]
			}
			resp, err := c.Diff(cmd.Context(), req)
			if err != nil {
				return friendly(err, g.socket)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(resp)
				if err != nil {
					return fmt.Errorf("encode: %w", err)
				}
				fmt.Fprintln(out, string(b))
				return nil
			}
			writeDiff(out, resp, noTrunc)
			counts := map[qtdv1.Change_Kind]int{}
			for _, ch := range resp.GetChanges() {
				counts[ch.GetKind()]++
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%d added, %d modified, %d deleted\n",
				counts[qtdv1.Change_KIND_ADDED], counts[qtdv1.Change_KIND_MODIFIED], counts[qtdv1.Change_KIND_DELETED])
			if resp.GetTruncated() {
				fmt.Fprintln(cmd.ErrOrStderr(), "qt: diff truncated: the sandbox has more changes than shown")
			}
			if len(args) == 2 && resp.GetEvents() != nil {
				writeEventsDiff(cmd, args[0], args[1], resp.GetEvents())
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON (full hashes, raw bytes of non-UTF-8 names)")
	cmd.Flags().BoolVar(&noTrunc, "no-trunc", false, "show full sha256 hashes")
	return cmd
}

func writeDiff(w io.Writer, resp *qtdv1.DiffResponse, noTrunc bool) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tMODE\tSIZE\tSHA256\tPATH")
	for _, ch := range resp.GetChanges() {
		kind := map[qtdv1.Change_Kind]string{qtdv1.Change_KIND_ADDED: "A", qtdv1.Change_KIND_MODIFIED: "M", qtdv1.Change_KIND_DELETED: "D"}[ch.GetKind()]
		size, sum := "-", "-"
		mode := fileMode(ch.GetMode())
		if mode.IsRegular() || mode&fs.ModeSymlink != 0 {
			size = humanBytes(ch.GetSize())
		}
		if s := ch.GetSha256(); s != "" {
			sum = s
			if !noTrunc && len(s) > 12 {
				sum = s[:12]
			}
		}
		p := displayName(ch.GetPath(), ch.GetPathRaw())
		if mode&fs.ModeSymlink != 0 {
			p += " -> " + displayName(ch.GetLinkTarget(), ch.GetLinkTargetRaw())
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", kind, mode, size, sum, p)
	}
	_ = tw.Flush()
}

// displayName makes an untrusted name safe for a terminal: names with control characters,
// non-printable runes or invalid UTF-8 are shown Go-quoted (so escape sequences can't run).
func displayName(s string, raw []byte) string {
	if len(raw) > 0 {
		s = string(raw)
	}
	if !utf8.ValidString(s) || strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) && r != ' ' }) >= 0 {
		return strconv.Quote(s)
	}
	return s
}

// fileMode converts a POSIX st_mode back to an fs.FileMode for display.
func fileMode(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	if m&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}
	if m&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}
	if m&0o1000 != 0 {
		mode |= fs.ModeSticky
	}
	switch m & 0o170000 {
	case 0o040000:
		mode |= fs.ModeDir
	case 0o120000:
		mode |= fs.ModeSymlink
	case 0o010000:
		mode |= fs.ModeNamedPipe
	case 0o140000:
		mode |= fs.ModeSocket
	case 0o020000:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case 0o060000:
		mode |= fs.ModeDevice
	}
	return mode
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
