//! Procedurally generated icons for `output.resources.icon: random`.
//!
//! A synthetic, per-artifact icon avoids two problems of shipping one default:
//! a shared icon would be a static build fingerprint, and a real application's
//! icon drags its trademark along. The render is pure `std` and deterministic in
//! the seed, so the same seed always reproduces the same icon — the build
//! records it in the manifest.
//!
//! Cost constraint: the `.ico` is embedded without a PNG encoder (no extra
//! dependency), so every image is an uncompressed BMP `DIB` and the largest is
//! 64x64 (a single 256x256 DIB is ~262 KiB). Windows upscales the 64 for the
//! "extra large" shell views; a true 256 would need PNG compression, a
//! follow-up.

use super::icon::Icon;

/// Icon sizes, in pixels, embedded in every generated icon (ascending).
const SIZES: [usize; 4] = [16, 32, 48, 64];

/// Supersampled render size; downsampled to each entry of [`SIZES`].
const SS: usize = 256;

/// Number of glyph styles the seed can pick from.
const STYLE_COUNT: u64 = 5;

/// Renders a deterministic icon from `seed`.
pub fn generate(seed: u64) -> Icon {
    let mut rng = Prng::new(seed);
    let style = Style::from_index(rng.range(STYLE_COUNT));
    let big = render(&mut rng, style);

    let mut images = Vec::with_capacity(SIZES.len());
    let mut group = Vec::with_capacity(6 + SIZES.len() * 14);
    group.extend_from_slice(&0u16.to_le_bytes()); // reserved
    group.extend_from_slice(&1u16.to_le_bytes()); // type: icon
    group.extend_from_slice(&(SIZES.len() as u16).to_le_bytes());

    for (index, &size) in SIZES.iter().enumerate() {
        let rgb = resample(&big, SS, SS, size, size);
        let dib = dib_rgba(size, &rgb);

        // All sizes are < 256, so the width/height byte is the size itself.
        group.push(size as u8);
        group.push(size as u8);
        group.push(0); // color count
        group.push(0); // reserved
        group.extend_from_slice(&1u16.to_le_bytes()); // planes
        group.extend_from_slice(&32u16.to_le_bytes()); // bit count
        group.extend_from_slice(&(dib.len() as u32).to_le_bytes());
        group.extend_from_slice(&((index + 1) as u16).to_le_bytes()); // RT_ICON id

        images.push(dib);
    }

    Icon { images, group }
}

/// splitmix64: tiny, deterministic, good enough for a pleasant-looking palette.
struct Prng(u64);

impl Prng {
    fn new(seed: u64) -> Self {
        Prng(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn range(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    fn between(&mut self, a: f64, b: f64) -> f64 {
        a + (b - a) * self.f64()
    }
}

/// The glyph drawn over the gradient background.
#[derive(Clone, Copy)]
enum Style {
    Ring,
    Diamond,
    Chevron,
    Plus,
    Document,
}

impl Style {
    fn from_index(index: u64) -> Self {
        match index % STYLE_COUNT {
            0 => Style::Ring,
            1 => Style::Diamond,
            2 => Style::Chevron,
            3 => Style::Plus,
            _ => Style::Document,
        }
    }
}

// --- color -----------------------------------------------------------------

fn hsl(h: f64, s: f64, l: f64) -> [f64; 3] {
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let hp = h.rem_euclid(1.0) * 6.0;
    let x = c * (1.0 - ((hp % 2.0) - 1.0).abs());
    let (r, g, b) = match hp as i32 % 6 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let m = l - c / 2.0;
    [r + m, g + m, b + m]
}

fn mix(a: [f64; 3], b: [f64; 3], t: f64) -> [f64; 3] {
    [
        a[0] + (b[0] - a[0]) * t,
        a[1] + (b[1] - a[1]) * t,
        a[2] + (b[2] - a[2]) * t,
    ]
}

fn to_u8(c: [f64; 3]) -> [u8; 3] {
    [
        (c[0] * 255.0).round().clamp(0.0, 255.0) as u8,
        (c[1] * 255.0).round().clamp(0.0, 255.0) as u8,
        (c[2] * 255.0).round().clamp(0.0, 255.0) as u8,
    ]
}

// --- signed distance fields (pixels, negative = inside) --------------------

fn rounded_rect(px: f64, py: f64, cx: f64, cy: f64, hw: f64, hh: f64, r: f64) -> f64 {
    let qx = (px - cx).abs() - (hw - r);
    let qy = (py - cy).abs() - (hh - r);
    let ax = qx.max(0.0);
    let ay = qy.max(0.0);
    (ax * ax + ay * ay).sqrt() + qx.max(qy).min(0.0) - r
}

fn circle(px: f64, py: f64, cx: f64, cy: f64, r: f64) -> f64 {
    ((px - cx).powi(2) + (py - cy).powi(2)).sqrt() - r
}

fn segment(px: f64, py: f64, ax: f64, ay: f64, bx: f64, by: f64) -> f64 {
    let pax = px - ax;
    let pay = py - ay;
    let bax = bx - ax;
    let bay = by - ay;
    let h = ((pax * bax + pay * bay) / (bax * bax + bay * bay)).clamp(0.0, 1.0);
    let dx = pax - bax * h;
    let dy = pay - bay * h;
    (dx * dx + dy * dy).sqrt()
}

/// One-pixel analytic antialiasing from a signed distance.
fn coverage(d: f64) -> f64 {
    (0.5 - d).clamp(0.0, 1.0)
}

// --- rendering -------------------------------------------------------------

fn app_pixel(
    bg: [f64; 3],
    px: f64,
    py: f64,
    sdf: impl Fn(f64, f64) -> f64,
    shadow: [f64; 3],
    glyph: [f64; 3],
) -> [f64; 3] {
    let with_shadow = mix(bg, shadow, coverage(sdf(px - 5.0, py - 5.0)) * 0.35);
    mix(with_shadow, glyph, coverage(sdf(px, py)))
}

fn doc_pixel(bg: [f64; 3], px: f64, py: f64, cx: f64, cy: f64, shadow: [f64; 3]) -> [f64; 3] {
    let page = rounded_rect(px, py, cx, cy + 4.0, 46.0, 60.0, 9.0);
    let with_shadow = mix(
        bg,
        shadow,
        coverage(rounded_rect(
            px - 5.0,
            py - 5.0,
            cx,
            cy + 4.0,
            46.0,
            60.0,
            9.0,
        )) * 0.35,
    );
    let page_cov = coverage(page);
    let with_page = mix(with_shadow, [0.98, 0.98, 1.0], page_cov);

    let lines = [(-36.0, 30.0), (-20.0, 30.0), (-4.0, 30.0), (12.0, 18.0)];
    let mut d = f64::INFINITY;
    for (ly, half) in lines {
        d = d.min(rounded_rect(px, py, cx, cy + 4.0 + ly, half, 3.0, 1.5));
    }
    mix(with_page, [0.55, 0.57, 0.62], coverage(d) * page_cov)
}

/// Draws the icon at [`SS`]x[`SS`] as flat RGB (opaque; the background bleeds to
/// the edge).
#[allow(clippy::needless_range_loop)]
fn render(rng: &mut Prng, style: Style) -> Vec<u8> {
    let hue = rng.f64();
    let c1 = hsl(hue, rng.between(0.55, 0.78), rng.between(0.44, 0.52));
    let c2 = hsl(
        hue + rng.between(0.06, 0.18),
        rng.between(0.60, 0.82),
        rng.between(0.28, 0.40),
    );
    let angle = rng.between(0.0, std::f64::consts::TAU);
    let (gdx, gdy) = (angle.cos(), angle.sin());

    let shadow = [c2[0] * 0.35, c2[1] * 0.35, c2[2] * 0.35];
    let glyph = [1.0, 1.0, 1.0];
    let cx = SS as f64 / 2.0;
    let cy = SS as f64 / 2.0;

    let mut out = vec![0u8; SS * SS * 3];
    for y in 0..SS {
        for x in 0..SS {
            let px = x as f64 + 0.5;
            let py = y as f64 + 0.5;
            let t = (0.5 + ((px - cx) * gdx + (py - cy) * gdy) / SS as f64).clamp(0.0, 1.0);
            let bg = mix(c1, c2, t);

            let col = match style {
                Style::Ring => app_pixel(
                    bg,
                    px,
                    py,
                    |x, y| circle(x, y, cx, cy, 60.0).abs() - 9.0,
                    shadow,
                    glyph,
                ),
                Style::Diamond => app_pixel(
                    bg,
                    px,
                    py,
                    |x, y| ((x - cx).abs() + (y - cy).abs()) - 66.0,
                    shadow,
                    glyph,
                ),
                Style::Chevron => app_pixel(
                    bg,
                    px,
                    py,
                    |x, y| {
                        let a = segment(x, y, cx - 42.0, cy - 48.0, cx + 38.0, cy);
                        let b = segment(x, y, cx + 38.0, cy, cx - 42.0, cy + 48.0);
                        a.min(b) - 15.0
                    },
                    shadow,
                    glyph,
                ),
                Style::Plus => app_pixel(
                    bg,
                    px,
                    py,
                    |x, y| {
                        let v = rounded_rect(x, y, cx, cy, 17.0, 64.0, 8.0);
                        let h = rounded_rect(x, y, cx, cy, 64.0, 17.0, 8.0);
                        v.min(h)
                    },
                    shadow,
                    glyph,
                ),
                Style::Document => doc_pixel(bg, px, py, cx, cy, shadow),
            };

            let o = (y * SS + x) * 3;
            let bytes = to_u8(col);
            out[o] = bytes[0];
            out[o + 1] = bytes[1];
            out[o + 2] = bytes[2];
        }
    }
    out
}

// --- resampling ------------------------------------------------------------

fn overlap(a0: f64, a1: f64, b0: f64, b1: f64) -> f64 {
    (a1.min(b1) - a0.max(b0)).max(0.0)
}

/// Area-weighted box filter from `sw`x`sh` to `tw`x`th`.
#[allow(clippy::needless_range_loop)]
fn resample(src: &[u8], sw: usize, sh: usize, tw: usize, th: usize) -> Vec<u8> {
    let mut out = vec![0u8; tw * th * 3];
    let xr = sw as f64 / tw as f64;
    let yr = sh as f64 / th as f64;
    for ty in 0..th {
        let sy0 = ty as f64 * yr;
        let sy1 = sy0 + yr;
        let iy0 = sy0.floor() as usize;
        let iy1 = (sy1.ceil() as usize).min(sh);
        for tx in 0..tw {
            let sx0 = tx as f64 * xr;
            let sx1 = sx0 + xr;
            let ix0 = sx0.floor() as usize;
            let ix1 = (sx1.ceil() as usize).min(sw);
            let mut acc = [0.0f64; 3];
            let mut weight = 0.0f64;
            for sy in iy0..iy1 {
                let oy = overlap(sy as f64, sy as f64 + 1.0, sy0, sy1);
                if oy <= 0.0 {
                    continue;
                }
                for sx in ix0..ix1 {
                    let ox = overlap(sx as f64, sx as f64 + 1.0, sx0, sx1);
                    let w = ox * oy;
                    if w <= 0.0 {
                        continue;
                    }
                    let idx = (sy * sw + sx) * 3;
                    acc[0] += src[idx] as f64 * w;
                    acc[1] += src[idx + 1] as f64 * w;
                    acc[2] += src[idx + 2] as f64 * w;
                    weight += w;
                }
            }
            if weight > 0.0 {
                let o = (ty * tw + tx) * 3;
                out[o] = (acc[0] / weight).round() as u8;
                out[o + 1] = (acc[1] / weight).round() as u8;
                out[o + 2] = (acc[2] / weight).round() as u8;
            }
        }
    }
    out
}

// --- BMP DIB image ---------------------------------------------------------

/// A 32-bit `BITMAPINFOHEADER` DIB (bottom-up BGRA + an all-zero AND mask), the
/// classic `.ico` image format.
fn dib_rgba(size: usize, rgb: &[u8]) -> Vec<u8> {
    let w = size;
    let h = size;
    let mask_row = w.div_ceil(32) * 4;
    let mut d = Vec::with_capacity(40 + w * h * 4 + mask_row * h);
    d.extend_from_slice(&40u32.to_le_bytes()); // BITMAPINFOHEADER size
    d.extend_from_slice(&(w as i32).to_le_bytes());
    d.extend_from_slice(&((h * 2) as i32).to_le_bytes()); // height + AND mask
    d.extend_from_slice(&1u16.to_le_bytes()); // planes
    d.extend_from_slice(&32u16.to_le_bytes()); // bit count
    d.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
    d.extend_from_slice(&((w * h * 4 + mask_row * h) as u32).to_le_bytes());
    for _ in 0..4 {
        d.extend_from_slice(&0u32.to_le_bytes()); // ppm x/y, clrused, clrimp
    }
    for y in (0..h).rev() {
        for x in 0..w {
            let i = (y * w + x) * 3;
            d.push(rgb[i + 2]);
            d.push(rgb[i + 1]);
            d.push(rgb[i]);
            d.push(255);
        }
    }
    d.resize(d.len() + mask_row * h, 0); // AND mask
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_the_declared_images_and_a_matching_group() {
        let icon = generate(0x1234_5678);
        assert_eq!(icon.images.len(), SIZES.len());
        assert_eq!(icon.group.len(), 6 + SIZES.len() * 14);
        // GRPICONDIR: reserved, type, count.
        assert_eq!(&icon.group[..6], &[0, 0, 1, 0, SIZES.len() as u8, 0]);
        // Each GRPICONDIRENTRY's id is its image's index + 1 (14-byte entries).
        for (index, _) in SIZES.iter().enumerate() {
            let entry = 6 + index * 14;
            let id = u16::from_le_bytes([icon.group[entry + 12], icon.group[entry + 13]]);
            assert_eq!(id as usize, index + 1);
        }
    }

    #[test]
    fn every_image_is_a_32bpp_dib_of_its_size() {
        let icon = generate(42);
        for (index, &size) in SIZES.iter().enumerate() {
            let dib = &icon.images[index];
            let header_size = u32::from_le_bytes([dib[0], dib[1], dib[2], dib[3]]);
            assert_eq!(header_size, 40);
            let width = i32::from_le_bytes([dib[4], dib[5], dib[6], dib[7]]);
            let height = i32::from_le_bytes([dib[8], dib[9], dib[10], dib[11]]);
            assert_eq!(width as usize, size);
            assert_eq!(height as usize, size * 2, "height includes the AND mask");
            let bit_count = u16::from_le_bytes([dib[14], dib[15]]);
            assert_eq!(bit_count, 32);
        }
    }

    #[test]
    fn is_deterministic_in_the_seed() {
        let first = generate(0xDEAD_BEEF);
        let second = generate(0xDEAD_BEEF);
        assert_eq!(first.images, second.images);
        assert_eq!(first.group, second.group);
    }

    #[test]
    fn different_seeds_produce_different_icons() {
        // Seeds 1 and 2 pick different glyph styles, so the pixels must differ.
        assert_ne!(generate(1).images, generate(2).images);
    }
}
