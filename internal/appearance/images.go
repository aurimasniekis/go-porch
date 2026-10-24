package appearance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	_ "image/gif" // decoder
	"image/jpeg"
	"image/png"

	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp" // decoder for uploaded and fetched icons
)

// Limits for images Porch accepts (ADR-0045). Dimensions are checked from the header before the pixels are decoded,
// so a small file cannot expand into a huge allocation.
const (
	maxSourcePixels  = 64 << 20 // 64 MP
	maxIconBytes     = 2 << 20
	maxBgBytes       = 25 << 20
	iconSize         = 256
	backgroundWidth  = 2560
	backgroundHeight = 1600
	jpegQuality      = 82
)

// ErrImage reports an upload or download that is not an acceptable image.
var ErrImage = errors.New("appearance: not an acceptable image")

// Encoded is an image re-encoded by Porch: only these bytes are ever stored and served.
type Encoded struct {
	ID          string // hex SHA-256 of Data
	ContentType string
	Data        []byte
	Width       int
	Height      int
}

func decode(b []byte) (image.Image, error) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrImage, err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > maxSourcePixels {
		return nil, fmt.Errorf("%w: %dx%d pixels", ErrImage, cfg.Width, cfg.Height)
	}
	img, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrImage, err)
	}
	return img, nil
}

// fit scales img down (never up) to fit within w×h, keeping its aspect ratio.
func fit(img image.Image, w, h int) image.Image {
	b := img.Bounds()
	sw, sh := b.Dx(), b.Dy()
	if sw <= w && sh <= h {
		return img
	}
	scale := min(float64(w)/float64(sw), float64(h)/float64(sh))
	dw, dh := max(1, int(float64(sw)*scale)), max(1, int(float64(sh)*scale))
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, b, draw.Src, nil)
	return dst
}

func encoded(ct string, data []byte, img image.Image) Encoded {
	sum := sha256.Sum256(data)
	return Encoded{ID: hex.EncodeToString(sum[:]), ContentType: ct, Data: data, Width: img.Bounds().Dx(), Height: img.Bounds().Dy()}
}

// EncodeIcon turns an icon into what Porch stores: SVG is sanitized and kept as SVG (it scales cleanly); PNG, JPEG,
// GIF or WebP becomes a PNG of at most 256×256 (transparency kept).
func EncodeIcon(b []byte) (Encoded, error) {
	if IsSVG(b) {
		return SanitizeSVG(b)
	}
	if len(b) > maxIconBytes {
		return Encoded{}, fmt.Errorf("%w: larger than %d bytes", ErrImage, maxIconBytes)
	}
	img, err := decode(b)
	if err != nil {
		return Encoded{}, err
	}
	img = fit(img, iconSize, iconSize)
	var buf bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&buf, img); err != nil {
		return Encoded{}, err
	}
	return encoded("image/png", buf.Bytes(), img), nil
}

// EncodeBackground turns a photo into a JPEG of at most 2560×1600. Portrait images and panoramas wider than 2.6:1
// are refused: they make poor page backgrounds.
func EncodeBackground(b []byte) (Encoded, error) {
	if len(b) > maxBgBytes {
		return Encoded{}, fmt.Errorf("%w: larger than %d bytes", ErrImage, maxBgBytes)
	}
	img, err := decode(b)
	if err != nil {
		return Encoded{}, err
	}
	if r := img.Bounds(); r.Dx() < r.Dy() {
		return Encoded{}, fmt.Errorf("%w: portrait orientation", ErrImage)
	} else if r.Dx()*10 > r.Dy()*26 {
		return Encoded{}, fmt.Errorf("%w: panorama (wider than 2.6:1)", ErrImage)
	}
	img = fit(img, backgroundWidth, backgroundHeight)
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: jpegQuality}); err != nil {
		return Encoded{}, err
	}
	return encoded("image/jpeg", buf.Bytes(), img), nil
}
