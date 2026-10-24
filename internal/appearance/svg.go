package appearance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const maxSVGBytes = 512 << 10

// svgElements are the SVG elements an icon may use: shapes, paint servers, clipping, masking, text and filters.
// Anything else (script, foreignObject, image, a, animate*, iframe…) is dropped with its whole subtree.
var svgElements = map[string]bool{
	"svg": true, "g": true, "defs": true, "symbol": true, "use": true, "title": true, "desc": true, "style": true,
	"path": true, "rect": true, "circle": true, "ellipse": true, "line": true, "polyline": true, "polygon": true,
	"text": true, "tspan": true, "textPath": true,
	"linearGradient": true, "radialGradient": true, "stop": true, "pattern": true, "clipPath": true, "mask": true, "marker": true,
	"filter": true, "feGaussianBlur": true, "feOffset": true, "feBlend": true, "feColorMatrix": true, "feFlood": true,
	"feComposite": true, "feMerge": true, "feMergeNode": true, "feDropShadow": true, "feMorphology": true,
}

var (
	// Values that could load or run something. url(#id) references inside the document are allowed.
	badValue  = regexp.MustCompile(`(?i)javascript:|vbscript:|data:|expression\s*\(|@import|url\s*\(\s*['"]?\s*[^'"#\s)]`)
	attrName  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]*$`)
	svgPrefix = regexp.MustCompile(`^\s*(<\?xml[^>]*\?>\s*)?(<!--[\s\S]*?-->\s*)*<svg[\s>]`)
)

// IsSVG reports whether b looks like an SVG document (possibly after an XML declaration and comments).
func IsSVG(b []byte) bool { return svgPrefix.Match(b) }

// SanitizeSVG rewrites an SVG icon from an allowlist (ADR-0045): only allowed elements are kept, event handlers and
// links out of the document are removed, and DOCTYPEs (entity expansion) are refused. The output is re-serialized
// by Porch, never passed through, and is served with a sandboxing CSP as well.
func SanitizeSVG(b []byte) (Encoded, error) {
	if len(b) > maxSVGBytes {
		return Encoded{}, fmt.Errorf("%w: SVG larger than %d bytes", ErrImage, maxSVGBytes)
	}
	if !IsSVG(b) {
		return Encoded{}, fmt.Errorf("%w: not an SVG document", ErrImage)
	}
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = true
	var out bytes.Buffer
	skip := 0 // depth inside a dropped element
	open := 0
	sawRoot := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Encoded{}, fmt.Errorf("%w: %w", ErrImage, err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return Encoded{}, fmt.Errorf("%w: SVG with a DOCTYPE or other directive", ErrImage)
		case xml.ProcInst, xml.Comment:
			continue
		case xml.StartElement:
			if skip > 0 || !svgElements[t.Name.Local] || (t.Name.Space != "" && t.Name.Space != "http://www.w3.org/2000/svg") {
				skip++
				continue
			}
			if !sawRoot && t.Name.Local != "svg" {
				return Encoded{}, fmt.Errorf("%w: root element is not svg", ErrImage)
			}
			out.WriteString("<" + t.Name.Local)
			if !sawRoot {
				out.WriteString(` xmlns="http://www.w3.org/2000/svg"`)
				sawRoot = true
			}
			for _, a := range t.Attr {
				name := a.Name.Local
				if a.Name.Space == "xmlns" || name == "xmlns" || !attrName.MatchString(name) || strings.HasPrefix(strings.ToLower(name), "on") {
					continue
				}
				if a.Name.Space != "" && a.Name.Space != "http://www.w3.org/1999/xlink" && a.Name.Space != "http://www.w3.org/XML/1998/namespace" {
					continue
				}
				if name == "href" && !strings.HasPrefix(strings.TrimSpace(a.Value), "#") {
					continue // only references inside the document
				}
				if badValue.MatchString(a.Value) {
					continue
				}
				out.WriteString(" " + name + `="`)
				_ = xml.EscapeText(&out, []byte(a.Value))
				out.WriteString(`"`)
			}
			out.WriteString(">")
			open++
		case xml.EndElement:
			if skip > 0 {
				skip--
				continue
			}
			out.WriteString("</" + t.Name.Local + ">")
			open--
		case xml.CharData:
			if skip > 0 || open == 0 {
				continue
			}
			if badValue.Match(t) {
				return Encoded{}, fmt.Errorf("%w: SVG text or style that loads external content", ErrImage)
			}
			_ = xml.EscapeText(&out, t)
		}
	}
	if !sawRoot || open != 0 {
		return Encoded{}, fmt.Errorf("%w: incomplete SVG document", ErrImage)
	}
	data := out.Bytes()
	sum := sha256.Sum256(data)
	return Encoded{ID: hex.EncodeToString(sum[:]), ContentType: "image/svg+xml", Data: data}, nil
}
