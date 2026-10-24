package appearance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Fetcher downloads images and their attribution from the open sources Porch supports (ADR-0045). Its client must
// come from the outbound guard, so every connection (including redirects) goes to public addresses only.
type Fetcher struct {
	Client    *http.Client
	UserAgent string // Wikimedia asks every API client for a descriptive User-Agent with contact information
	// Endpoints, overridable in tests.
	WikimediaAPI   string // default https://commons.wikimedia.org/w/api.php
	PicsumAPI      string // default https://picsum.photos
	DashboardIcons string // default https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons
	// TheSVGBase replaces theSVG's sources (default: https://thesvg.org/icons, then the GitHub repository; jsDelivr
	// refuses the repository, which is larger than its 50 MB package limit).
	TheSVGBase string
}

// Candidate is a background image before it is downloaded.
type Candidate struct {
	URL        string
	Title      string
	Author     string
	License    string
	LicenseURL string
	SourceURL  string
}

func (f *Fetcher) or(v, def string) string {
	if v != "" {
		return strings.TrimRight(v, "/")
	}
	return def
}

func (f *Fetcher) get(ctx context.Context, u string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.UserAgent)
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", redactQuery(u), resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("GET %s: response larger than %d bytes", redactQuery(u), limit)
	}
	return b, nil
}

func redactQuery(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i]
	}
	return u
}

// Image downloads one image (at most limit bytes).
func (f *Fetcher) Image(ctx context.Context, u string, limit int64) ([]byte, error) {
	pu, err := url.Parse(u)
	if err != nil || pu.Scheme != "https" || pu.Host == "" || pu.User != nil {
		return nil, fmt.Errorf("%w: image URL must be https", ErrImage)
	}
	return f.get(ctx, pu.String(), limit)
}

// dashboardIconName is the file-name syntax of the dashboard-icons set.
var dashboardIconName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,99}$`)

// DashboardIcon downloads a named icon from the dashboard-icons set (Apache-2.0): the SVG when there is one,
// otherwise the PNG.
func (f *Fetcher) DashboardIcon(ctx context.Context, name string) ([]byte, error) {
	if !dashboardIconName.MatchString(name) {
		return nil, fmt.Errorf("%w: icon names are lowercase letters, digits and dashes", ErrImage)
	}
	base := f.or(f.DashboardIcons, "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons")
	if b, err := f.get(ctx, base+"/svg/"+name+".svg", maxSVGBytes); err == nil {
		return b, nil
	}
	return f.get(ctx, base+"/png/"+name+".png", maxIconBytes)
}

// theSVGRef is "slug" or "slug/variant" in the theSVG brand library (default, mono, light, dark, wordmark, …).
var theSVGRef = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{0,99})(?:/([a-z][a-z0-9-]{0,39}))?$`)

// TheSVG downloads a brand logo from theSVG (glincker/thesvg). Logos carry their brands' own licences and trademarks.
func (f *Fetcher) TheSVG(ctx context.Context, ref string) ([]byte, error) {
	m := theSVGRef.FindStringSubmatch(ref)
	if m == nil {
		return nil, fmt.Errorf("%w: theSVG icons are named slug or slug/variant, e.g. grafana or github/mono", ErrImage)
	}
	variant := m[2]
	if variant == "" {
		variant = "default"
	}
	bases := []string{"https://thesvg.org/icons", "https://raw.githubusercontent.com/glincker/thesvg/main/public/icons"}
	if f.TheSVGBase != "" {
		bases = []string{strings.TrimRight(f.TheSVGBase, "/")}
	}
	var err error
	for _, base := range bases {
		var b []byte
		if b, err = f.get(ctx, base+"/"+m[1]+"/"+variant+".svg", maxSVGBytes); err == nil {
			return b, nil
		}
	}
	return nil, err
}

// ---- Wikimedia Commons ----

type wmResponse struct {
	Continue map[string]string `json:"continue"`
	Query    struct {
		Members []struct {
			Title string `json:"title"`
		} `json:"categorymembers"`
		Pages map[string]struct {
			Title     string `json:"title"`
			ImageInfo []struct {
				ThumbURL       string `json:"thumburl"`
				DescriptionURL string `json:"descriptionurl"`
				Mime           string `json:"mime"`
				Width          int    `json:"width"`
				Height         int    `json:"height"`
				// Values are usually strings, sometimes numbers or other JSON.
				Ext map[string]struct {
					Value json.RawMessage `json:"value"`
				} `json:"extmetadata"`
			} `json:"imageinfo"`
		} `json:"pages"`
	} `json:"query"`
}

func (f *Fetcher) wikimedia(ctx context.Context, params url.Values) (wmResponse, error) {
	params.Set("action", "query")
	params.Set("format", "json")
	var out wmResponse
	b, err := f.get(ctx, f.or(f.WikimediaAPI, "https://commons.wikimedia.org/w/api.php")+"?"+params.Encode(), 4<<20)
	if err != nil {
		return out, err
	}
	return out, json.Unmarshal(b, &out)
}

var tags = regexp.MustCompile(`<[^>]*>`)

// meta returns a Commons metadata value as plain text, whatever JSON type it has.
func meta(v json.RawMessage) string {
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return plain(s)
	}
	return plain(string(v))
}

// plain turns Commons' HTML metadata into plain text.
func plain(s string) string {
	return strings.Join(strings.Fields(html.UnescapeString(tags.ReplaceAllString(s, " "))), " ")
}

// WikimediaCandidates returns up to n landscape photos: the named files when given, otherwise a random sample of the
// category's files.
func (f *Fetcher) WikimediaCandidates(ctx context.Context, category string, files []string, n int) ([]Candidate, error) {
	titles := make([]string, 0, len(files))
	for _, name := range files {
		titles = append(titles, "File:"+strings.TrimPrefix(name, "File:"))
	}
	if len(titles) == 0 {
		var all []string
		params := url.Values{"list": {"categorymembers"}, "cmtitle": {"Category:" + strings.TrimPrefix(category, "Category:")},
			"cmtype": {"file"}, "cmlimit": {"500"}}
		for page := 0; page < 4; page++ { // at most 2000 files are considered
			r, err := f.wikimedia(ctx, params)
			if err != nil {
				return nil, err
			}
			for _, m := range r.Query.Members {
				if lower := strings.ToLower(m.Title); strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".jpeg") {
					all = append(all, m.Title)
				}
			}
			next := r.Continue["cmcontinue"]
			if next == "" {
				break
			}
			params.Set("cmcontinue", next)
		}
		if len(all) == 0 {
			return nil, fmt.Errorf("wikimedia: category %q has no JPEG files", category)
		}
		shuffle(all)
		titles = all[:min(len(all), n*3)] // some are skipped below (portrait, missing license)
	}
	var out []Candidate
	for start := 0; start < len(titles) && len(out) < n; start += 50 {
		batch := titles[start:min(start+50, len(titles))]
		r, err := f.wikimedia(ctx, url.Values{"titles": {strings.Join(batch, "|")}, "prop": {"imageinfo"},
			"iiprop": {"url|mime|size|extmetadata"}, "iiurlwidth": {strconv.Itoa(backgroundWidth)}})
		if err != nil {
			return nil, err
		}
		for _, p := range r.Query.Pages {
			if len(p.ImageInfo) == 0 || len(out) >= n {
				continue
			}
			ii := p.ImageInfo[0]
			license := meta(ii.Ext["LicenseShortName"].Value)
			if ii.ThumbURL == "" || ii.Mime != "image/jpeg" || ii.Width < ii.Height || ii.Width*10 > ii.Height*26 || license == "" {
				continue
			}
			title := meta(ii.Ext["ObjectName"].Value)
			if title == "" {
				title = strings.TrimSuffix(strings.TrimPrefix(p.Title, "File:"), ".jpg")
			}
			out = append(out, Candidate{URL: ii.ThumbURL, Title: title, Author: meta(ii.Ext["Artist"].Value), License: license,
				LicenseURL: meta(ii.Ext["LicenseUrl"].Value), SourceURL: ii.DescriptionURL})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("wikimedia: no usable landscape images")
	}
	return out, nil
}

// ---- Picsum (photos from Unsplash) ----

type picsumInfo struct {
	ID     string `json:"id"`
	Author string `json:"author"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	URL    string `json:"url"`
}

func (f *Fetcher) picsumCandidate(p picsumInfo) Candidate {
	return Candidate{URL: fmt.Sprintf("%s/id/%s/%d/%d.jpg", f.or(f.PicsumAPI, "https://picsum.photos"), p.ID, backgroundWidth, backgroundHeight),
		Title: "Photo " + p.ID, Author: p.Author, License: "Unsplash License", LicenseURL: "https://unsplash.com/license", SourceURL: p.URL}
}

// PicsumCandidates returns up to n photos: the given IDs, or a random sample.
func (f *Fetcher) PicsumCandidates(ctx context.Context, ids []string, n int) ([]Candidate, error) {
	base := f.or(f.PicsumAPI, "https://picsum.photos")
	var out []Candidate
	if len(ids) > 0 {
		for _, id := range ids {
			if _, err := strconv.Atoi(id); err != nil {
				return nil, fmt.Errorf("picsum: %q is not a photo ID", id)
			}
			b, err := f.get(ctx, base+"/id/"+id+"/info", 64<<10)
			if err != nil {
				return nil, err
			}
			var p picsumInfo
			if err := json.Unmarshal(b, &p); err != nil {
				return nil, err
			}
			out = append(out, f.picsumCandidate(p))
		}
		return out, nil
	}
	seen := map[string]bool{}
	for tries := 0; tries < 4 && len(out) < n; tries++ {
		b, err := f.get(ctx, fmt.Sprintf("%s/v2/list?page=%d&limit=100", base, 1+randN(10)), 1<<20)
		if err != nil {
			return nil, err
		}
		var list []picsumInfo
		if err := json.Unmarshal(b, &list); err != nil {
			return nil, err
		}
		shuffle(list)
		for _, p := range list {
			if len(out) < n && !seen[p.ID] && p.Width >= p.Height {
				seen[p.ID] = true
				out = append(out, f.picsumCandidate(p))
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("picsum: no usable photos")
	}
	return out, nil
}
