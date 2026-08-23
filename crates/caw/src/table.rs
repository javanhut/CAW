//! Aligned column output.
//!
//! One renderer behind every table caw prints, so `caw scan` lines up the way
//! `caw ports` does instead of drifting apart as columns are added.

/// Render `rows` beneath `headers`, padding every column but the last to its
/// widest cell and separating columns by two spaces.
///
/// The last column stays ragged: it is the one that can be long — an address
/// list, a security name — and padding it would only add trailing space.
///
/// Each line is returned newline-terminated, so the caller `print!`s the
/// result rather than looping.
pub fn render(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| width(h)).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(width(cell));
        }
    }

    let mut out = String::new();
    push_row(&mut out, &widths, headers.iter().copied());
    for row in rows {
        push_row(&mut out, &widths, row.iter().map(String::as_str));
    }
    out
}

/// Cell width in `char`s rather than bytes.
///
/// An SSID is arbitrary UTF-8, and byte length would push every column after a
/// non-ASCII name out of true. This is still not display width — a CJK name
/// occupies two cells per `char` — but correcting for that needs East Asian
/// width tables, which is more machinery than an occasional wide SSID earns.
fn width(s: &str) -> usize {
    s.chars().count()
}

fn push_row<'a>(out: &mut String, widths: &[usize], cells: impl Iterator<Item = &'a str>) {
    let mut line = String::new();
    for (i, cell) in cells.enumerate() {
        line.push_str(cell);
        if i + 1 < widths.len() {
            let pad = widths[i].saturating_sub(width(cell)) + 2;
            line.extend(std::iter::repeat_n(' ', pad));
        }
    }
    // A short or empty final cell would otherwise leave the padding of the
    // column before it dangling at the end of the line.
    out.push_str(line.trim_end());
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(cells: &[&[&str]]) -> Vec<Vec<String>> {
        cells
            .iter()
            .map(|r| r.iter().map(|c| (*c).to_owned()).collect())
            .collect()
    }

    /// The exact `caw ports` output the README documents. The port commands
    /// must keep printing this, so it is pinned against the shared renderer.
    #[test]
    fn matches_documented_ports_output() {
        let table = render(
            &["NAME", "TYPE", "STATE", "MAC", "ADDRESSES"],
            &rows(&[
                &["lo", "loopback", "up", "-", "127.0.0.1/8, ::1/128"],
                &[
                    "eth0",
                    "ethernet",
                    "up",
                    "5a:94:ef:e4:0c:ee",
                    "192.168.1.24/24",
                ],
                &["wlan0", "wireless", "no-carrier", "02:00:00:00:00:00", "-"],
            ]),
        );

        assert_eq!(
            table,
            "\
NAME   TYPE      STATE       MAC                ADDRESSES
lo     loopback  up          -                  127.0.0.1/8, ::1/128
eth0   ethernet  up          5a:94:ef:e4:0c:ee  192.168.1.24/24
wlan0  wireless  no-carrier  02:00:00:00:00:00  -
"
        );
    }

    #[test]
    fn a_column_widens_to_its_widest_cell_header_included() {
        let table = render(&["N", "V"], &rows(&[&["a", "1"], &["longer", "2"]]));
        assert_eq!(
            table,
            "N       V
a       1
longer  2
"
        );

        let table = render(&["HEADER", "V"], &rows(&[&["a", "1"]]));
        assert_eq!(
            table,
            "HEADER  V
a       1
"
        );
    }

    /// Widths are counted in `char`s: a UTF-8 SSID has more bytes than
    /// columns, and `len()` here would indent every row beneath it.
    #[test]
    fn non_ascii_cells_do_not_skew_the_next_column() {
        let table = render(
            &["SSID", "SECURITY"],
            &rows(&[&["café", "Open"], &["ab", "Open"]]),
        );
        assert_eq!(
            table,
            "SSID  SECURITY
café  Open
ab    Open
"
        );
    }

    /// An empty final cell must not leave the previous column's padding
    /// hanging off the end of the line.
    #[test]
    fn trailing_empty_cell_leaves_no_whitespace() {
        assert_eq!(
            render(&["A", "B"], &rows(&[&["x", ""], &["y", "z"]])),
            "A  B\nx\ny  z\n"
        );
    }

    #[test]
    fn headers_alone_still_render() {
        assert_eq!(render(&["A", "B"], &[]), "A  B\n");
    }
}
