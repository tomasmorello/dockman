package files

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RA341/dockman/internal/host/filesystem"
	"github.com/RA341/dockman/internal/host/middleware"
	"github.com/stretchr/testify/require"
)

// TestLoadFile_NeverServesFromCache guards against a regression where the
// editor's file-load endpoint used http.ServeContent with the file's real
// mtime, making it eligible for conditional-GET (If-Modified-Since) caching.
// Two different files can share an mtime (e.g. deployed together), and a
// browser (Safari does this readily) that had already cached one file's
// response could then get a bare 304 for a different file's URL and keep
// showing the wrong, previously-cached stack's compose content in the
// editor. This endpoint serves live, frequently-edited content: it must
// never be conditionally cacheable, regardless of the underlying file's
// on-disk timestamp.
func TestLoadFile_NeverServesFromCache(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	// "compose" is the alias segment the FSProvider below resolves and
	// strips; the file actually lives at root/litellm/docker-compose.yml,
	// matching how a real alias root works (see LoadFs).
	const filename = "compose/litellm/docker-compose.yml"
	const content = "services:\n  litellm:\n    image: litellm\n"
	require.NoError(t, os.MkdirAll(filepath.Join(root, "litellm"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "litellm", "docker-compose.yml"), []byte(content), 0o644))

	srv := New(func(host, alias string) (filesystem.FileSystem, error) {
		return filesystem.NewLocal(root), nil
	}, nil)
	handler := NewFileHandler(srv)

	doRequest := func(ifModifiedSince string) *httptest.ResponseRecorder {
		// mirrors the frontend's encodeURIComponent(fullPath): the slashes
		// are escaped so the whole path travels as the single {filename}
		// segment the route expects.
		req := httptest.NewRequest(http.MethodGet, "/load/"+url.PathEscape(filename), nil)
		req = req.WithContext(middleware.SetHost(req.Context(), "local"))
		if ifModifiedSince != "" {
			req.Header.Set("If-Modified-Since", ifModifiedSince)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// a plain load must always return the current bytes
	rec := doRequest("")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, content, rec.Body.String())
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	// a conditional request claiming a cached copy from far in the future
	// (what a browser sends once it has cached a Last-Modified for this
	// exact URL) must still return the full, current content — never a
	// bare 304 that would make the browser reuse a stale cached body.
	future := time.Now().Add(24 * time.Hour).UTC().Format(http.TimeFormat)
	rec = doRequest(future)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, content, rec.Body.String())
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}
