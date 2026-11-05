package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"math"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Both pictures are cut from docs/assets/banner.jpg: the cloud of light with the banner's own lettering
// painted out, and the brightness of the deer's white fur.
var (
	//go:embed banner_cloud.jpg
	bannerCloudJPEG []byte
	//go:embed banner_deer.png
	bannerDeerPNG []byte
)

const (
	bannerMaxWidth  = 220
	bannerMinWidth  = 76
	bannerMaxRows   = 20
	bannerCloudTop  = 30 // the part of the cloud picture the band shows
	bannerCloudEnd  = 540
	bannerQuadrants = " ▘▝▀▖▌▞▛▗▚▐▜▄▙▟█"
)

var wordmark = []string{
	" ██████╗███████╗██████╗ ██╗   ██╗██╗   ██╗███████╗",
	"██╔════╝██╔════╝██╔══██╗██║   ██║██║   ██║██╔════╝",
	"██║     █████╗  ██████╔╝██║   ██║██║   ██║███████╗",
	"██║     ██╔══╝  ██╔══██╗╚██╗ ██╔╝██║   ██║╚════██║",
	"╚██████╗███████╗██║  ██║ ╚████╔╝ ╚██████╔╝███████║",
	" ╚═════╝╚══════╝╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚══════╝",
}

type rgb struct{ r, g, b uint8 }

func mixRGB(a, b rgb, f float64) rgb {
	f = math.Max(0, math.Min(1, f))
	m := func(x, y uint8) uint8 { return uint8(float64(x) + (float64(y)-float64(x))*f) }
	return rgb{m(a.r, b.r), m(a.g, b.g), m(a.b, b.b)}
}

func (c rgb) lum() float64 { return 0.3*float64(c.r) + 0.59*float64(c.g) + 0.11*float64(c.b) }

func (c rgb) minChannel() uint8 { return min(c.r, c.g, c.b) }

func meanRGB(cs []rgb) rgb {
	var r, g, b int
	for _, c := range cs {
		r, g, b = r+int(c.r), g+int(c.g), b+int(c.b)
	}
	n := len(cs)
	return rgb{uint8(r / n), uint8(g / n), uint8(b / n)}
}

func bannerNoise(x, y float64) float64 {
	return (math.Sin(x*0.17+y*0.29) + math.Sin(x*0.07-y*0.41+1.3) + math.Sin(x*0.37+y*0.11+2.1)) / 3
}

// cloudPicture holds the decoded cloud as plain RGB, for quick sampling.
type cloudPicture struct {
	w, h int
	pix  []rgb
}

func loadCloud() (*cloudPicture, error) {
	img, err := jpeg.Decode(bytes.NewReader(bannerCloudJPEG))
	if err != nil {
		return nil, err
	}
	b := img.Bounds()
	p := &cloudPicture{w: b.Dx(), h: b.Dy(), pix: make([]rgb, b.Dx()*b.Dy())}
	for y := 0; y < p.h; y++ {
		for x := 0; x < p.w; x++ {
			r, g, bl, _ := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
			p.pix[y*p.w+x] = rgb{uint8(r >> 8), uint8(g >> 8), uint8(bl >> 8)}
		}
	}
	return p, nil
}

// sample returns the average color of an area, and its brightest pixel, so sparkles survive shrinking.
func (p *cloudPicture) sample(x0, x1, y0, y1 float64) (average, brightest rgb) {
	ax, ay := max(0, int(x0)), max(0, int(y0))
	bx, by := min(p.w, max(int(x1), int(x0)+1)), min(p.h, max(int(y1), int(y0)+1))
	var r, g, b, n int
	best := -1.0
	for y := ay; y < by; y++ {
		for x := ax; x < bx; x++ {
			c := p.pix[y*p.w+x]
			r, g, b, n = r+int(c.r), g+int(c.g), b+int(c.b), n+1
			if l := c.lum(); l > best {
				best, brightest = l, c
			}
		}
	}
	if n == 0 {
		return rgb{}, rgb{}
	}
	return rgb{uint8(r / n), uint8(g / n), uint8(b / n)}, brightest
}

// deerFur scales the deer's fur brightness to w by h, as values from 0 to 1.
func deerFur(w, h int) ([][]float64, error) {
	img, err := png.Decode(bytes.NewReader(bannerDeerPNG))
	if err != nil {
		return nil, err
	}
	gray := image.NewGray(img.Bounds())
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			gray.Set(x, y, img.At(x, y))
		}
	}
	out := make([][]float64, h)
	for y := range out {
		out[y] = make([]float64, w)
		y0, y1 := b.Min.Y+y*b.Dy()/h, b.Min.Y+(y+1)*b.Dy()/h
		for x := range out[y] {
			x0, x1 := b.Min.X+x*b.Dx()/w, b.Min.X+(x+1)*b.Dx()/w
			sum, n := 0, 0
			for sy := y0; sy < max(y1, y0+1); sy++ {
				for sx := x0; sx < max(x1, x0+1); sx++ {
					sum += int(gray.GrayAt(sx, sy).Y)
					n++
				}
			}
			out[y][x] = float64(sum) / float64(n) / 255
		}
	}
	return out, nil
}

// bannerDot is one braille dot of the scene. It may be lit (dot), and it may lie inside the cloud's body
// (base), which colors the cell behind it.
type bannerDot struct {
	lit, inBody bool
	dot, base   rgb
}

func writeCell(b *strings.Builder, bold bool, fg rgb, bg *rgb, ch rune) {
	b.WriteString("\x1b[")
	if bold {
		b.WriteString("1;")
	}
	fmt.Fprintf(b, "38;2;%d;%d;%d", fg.r, fg.g, fg.b)
	if bg != nil {
		fmt.Fprintf(b, ";48;2;%d;%d;%d", bg.r, bg.g, bg.b)
	}
	fmt.Fprintf(b, "m%c\x1b[0m", ch)
}

// renderBanner draws the opening banner for a terminal of the given size. With color it is a band as
// wide as the terminal: the banner's white deer, its cloud of light, and the wordmark in front. It
// returns nil when no scene fits. Without color it is only the wordmark.
func renderBanner(cols, lines int, color bool) []string {
	if !color {
		if cols > len([]rune(wordmark[0])) {
			return wordmark
		}
		return []string{"cervus"}
	}
	width := min(cols-1, bannerMaxWidth)
	rows := min(lines-4, max(10, min(bannerMaxRows, width*16/100)))
	if width < bannerMinWidth || rows < 8 {
		return nil
	}
	cloud, err := loadCloud()
	if err != nil {
		return nil
	}
	height, dotsWide := rows*4, width*2
	deerH := height - 1
	deerW := deerH * 430 / 720
	originX, originY := 2, (height-deerH)/2
	fur, err := deerFur(deerW, deerH)
	if err != nil {
		return nil
	}
	furAt := func(x, y int) float64 {
		if x < 0 || x >= deerW || y < 0 || y >= deerH {
			return 0
		}
		return fur[y][x]
	}
	start := originX + deerW*72/100 // the cloud trails from the deer
	textW := len([]rune(wordmark[0]))
	deerCols := (originX + deerW) / 2
	textX := deerCols + max(1, (width-deerCols-textW)/2)
	if textX+textW >= width {
		textX = width - textW - 1
	}
	textRow := (rows - len(wordmark)) / 2

	// A fixed seed: the banner looks the same on every run.
	rnd := rand.New(rand.NewSource(7))
	dots := make([]bannerDot, dotsWide*height)
	at := func(x, y int) *bannerDot { return &dots[y*dotsWide+x] }

	bayer := [4][2]float64{{0, 4}, {6, 2}, {1, 5}, {7, 3}}
	span := dotsWide - start
	srcH := float64(bannerCloudEnd-bannerCloudTop) / float64(height)
	srcW := float64(cloud.w)
	passes := max(1, int(math.Ceil(float64(span)*srcH/(srcW*1.6)))) // mirrored passes over the picture
	srcStep := srcW * float64(passes) / float64(span)
	fold := func(v float64) float64 {
		v = math.Mod(v, 2*srcW)
		if v < srcW {
			return v
		}
		return 2*srcW - v
	}
	for py := 0; py < height; py++ {
		for px := start; px < dotsWide; px++ {
			v := float64(px-start) * srcStep
			t := float64(px-start) / float64(max(1, span-1))
			center := float64(height) * (0.50 - 0.05*math.Sin(math.Pi*t) + 0.03*math.Sin(t*9))
			half := float64(height) * (0.05 + 0.47*math.Pow(math.Sin(math.Pi*math.Min(1, t*0.72)), 0.75))
			dist := math.Abs(float64(py)-center)/half + 0.13*bannerNoise(float64(px)*0.6, float64(py)*1.1)
			if dist > 1 {
				if dist < 1.5 && rnd.Float64() < 0.05*(1.5-dist)*2 { // loose particles past the edge
					*at(px, py) = bannerDot{lit: true, dot: mixRGB(rgb{90, 130, 245}, rgb{235, 242, 255}, rnd.Float64())}
				}
				continue
			}
			rim := math.Min(1, (1-dist)/0.3)
			a, b := fold(v), fold(v+srcStep)
			if b < a {
				a, b = b, a
			}
			y0 := bannerCloudTop + 26*math.Sin(v/170) + float64(py)*srcH // the wobble hides the mirroring
			avg, best := cloud.sample(a, b+1, y0, y0+srcH)
			spark := best.lum() > 205 && best.lum()-avg.lum() > 45
			if avg.lum() < 52 || float64(avg.b) < float64(avg.r)*0.9 {
				if spark && rnd.Float64() < 0.8 {
					*at(px, py) = bannerDot{lit: true, dot: best}
				}
				continue
			}
			fade := math.Min(1, 0.35+float64(px-start)/40) * rim
			white := avg.minChannel() > 165
			density := (0.34 + 0.62*math.Min(1, (avg.lum()-52)/120)) * fade
			if white {
				density = math.Max(density, 0.92)
			}
			d := bannerDot{lit: spark || density > (bayer[py%4][px%2]+rnd.Float64())/8}
			switch {
			case white:
				d.dot = mixRGB(avg, rgb{190, 212, 255}, 0.5)
			case spark:
				d.dot = best
			default:
				d.dot = mixRGB(avg, rgb{92, 136, 255}, 0.55) // saturated, like the banner
			}
			if dist < 0.72 {
				d.inBody, d.base = true, mixRGB(avg, rgb{58, 96, 226}, 0.6)
			}
			*at(px, py) = d
		}
	}

	// Clear space and a soft blue glow around the deer. The deer itself is drawn cell by cell below.
	for y := -2; y < deerH+2; y++ {
		for x := -2; x < deerW+2; x++ {
			X, Y := originX+x, originY+y
			if X < 0 || X >= dotsWide || Y < 0 || Y >= height {
				continue
			}
			near := 0.0
			for a := -2; a <= 2; a++ {
				for b := -2; b <= 2; b++ {
					near = math.Max(near, furAt(x+a, y+b))
				}
			}
			if near >= 0.3 || X < start+4 {
				if X < start+8 {
					*at(X, Y) = bannerDot{}
				}
				if near >= 0.3 && rnd.Float64() < 0.18 {
					*at(X, Y) = bannerDot{lit: true, dot: mixRGB(rgb{70, 110, 235}, rgb{170, 196, 255}, rnd.Float64())}
				}
			}
		}
	}

	furTone := func(v float64) rgb {
		return mixRGB(rgb{58, 86, 190}, rgb{255, 255, 255}, math.Pow(math.Min(1, v/0.72), 0.7))
	}
	darkBlue := rgb{12, 20, 74}
	white := rgb{255, 255, 255}
	quadrants := []rune(bannerQuadrants)
	dotBits := [4][2]int{{0x01, 0x08}, {0x02, 0x10}, {0x04, 0x20}, {0x40, 0x80}}
	letters := make([][]rune, len(wordmark))
	for i, line := range wordmark {
		letters[i] = []rune(line)
	}

	out := make([]string, rows)
	var sb strings.Builder
	for r := 0; r < rows; r++ {
		sb.Reset()
		for x := 0; x < width; x++ {
			var letter rune
			if r >= textRow && r < textRow+len(wordmark) && x >= textX && x < textX+textW {
				if c := letters[r-textRow][x-textX]; c != ' ' {
					letter = c
				}
			}
			// The deer: four quadrants per cell in two tones, so shape and fur shading both show.
			if letter == 0 {
				var q [4]float64
				for qy := 0; qy < 2; qy++ {
					for qx := 0; qx < 2; qx++ {
						q[qy*2+qx] = (furAt(x*2+qx-originX, r*4+qy*2-originY) + furAt(x*2+qx-originX, r*4+qy*2+1-originY)) / 2
					}
				}
				hi, lo := math.Max(math.Max(q[0], q[1]), math.Max(q[2], q[3])), math.Min(math.Min(q[0], q[1]), math.Min(q[2], q[3]))
				if hi >= 0.14 {
					mid := (hi + lo) / 2
					var hiSum, loSum float64
					var hiN, loN, mask int
					for n, v := range q {
						if v >= mid {
							hiSum, hiN, mask = hiSum+v, hiN+1, mask|1<<n
						} else {
							loSum, loN = loSum+v, loN+1
						}
					}
					var bg *rgb
					if loN > 0 && loSum/float64(loN) >= 0.07 {
						c := furTone(loSum / float64(loN))
						bg = &c
					}
					writeCell(&sb, false, furTone(hiSum/float64(hiN)), bg, quadrants[mask])
					continue
				}
			}
			bits := 0
			var lit, bases []rgb
			for j := 0; j < 4; j++ {
				for i := 0; i < 2; i++ {
					d := at(x*2+i, r*4+j)
					if d.inBody {
						bases = append(bases, d.base)
					}
					if d.lit {
						bits |= dotBits[j][i]
						lit = append(lit, d.dot)
					}
				}
			}
			switch {
			case letter == '█':
				// Nearly solid white with a little grain, so the letters stay in front of the cloud.
				bits = 0xFF
				for bit := 1; bit < 256; bit <<= 1 {
					if rnd.Float64() < 0.10 {
						bits &^= bit
					}
				}
				if rnd.Float64() < 0.30 {
					writeCell(&sb, false, white, nil, '█')
				} else {
					writeCell(&sb, false, white, &rgb{226, 234, 255}, rune(0x2800+bits))
				}
			case letter != 0:
				// The wordmark's line details, in white, over the cloud's own color.
				var bg *rgb
				if len(bases) > 0 {
					c := mixRGB(meanRGB(bases), darkBlue, 0.74)
					bg = &c
				}
				writeCell(&sb, true, rgb{236, 242, 255}, bg, letter)
			case len(lit) == 0 && len(bases) == 0:
				sb.WriteByte(' ')
			default:
				var bg *rgb
				if len(bases) >= 7 {
					c := meanRGB(bases)
					if c.lum() <= 140 {
						c = mixRGB(c, darkBlue, 0.74)
					}
					bg = &c
				}
				fg := rgb{}
				if len(lit) > 0 {
					fg = meanRGB(lit)
				} else if len(bases) > 0 {
					fg = meanRGB(bases)
				}
				writeCell(&sb, false, fg, bg, rune(0x2800+bits))
			}
		}
		out[r] = sb.String()
	}
	return out
}

// bannerUsesColor is true only where the scene will look right: 24-bit color, and not refused.
func bannerUsesColor() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	c := os.Getenv("COLORTERM")
	return c == "truecolor" || c == "24bit"
}

// terminalSize asks the terminal, then $COLUMNS and $LINES, then assumes the classic 80x24.
func terminalSize(f *os.File) (cols, lines int) {
	var ws struct{ row, col, xpixel, ypixel uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno == 0 && ws.col > 0 && ws.row > 0 {
		return int(ws.col), int(ws.row)
	}
	cols, lines = 80, 24
	if v, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && v > 0 {
		cols = v
	}
	if v, err := strconv.Atoi(os.Getenv("LINES")); err == nil && v > 0 {
		lines = v
	}
	return cols, lines
}

// printBanner shows the banner on a terminal, and prints nothing into a pipe or a file.
func printBanner(w io.Writer) {
	if !isTTY(os.Stdout) {
		return
	}
	cols, lines := terminalSize(os.Stdout)
	color := bannerUsesColor()
	out := renderBanner(cols, lines, color)
	if color && out == nil {
		out = renderBanner(cols, lines, false)
	}
	fmt.Fprintln(w, strings.Join(out, "\n"))
	fmt.Fprintln(w)
}
