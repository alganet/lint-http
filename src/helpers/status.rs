// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

/// Returns true if `status` is a redirection status (3xx).
pub fn is_redirection_status(status: u16) -> bool {
    (300..=399).contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirection_boundaries_and_neighbors() {
        assert!(!is_redirection_status(299));
        assert!(is_redirection_status(300));
        assert!(is_redirection_status(301));
        assert!(is_redirection_status(308));
        assert!(is_redirection_status(399));
        assert!(!is_redirection_status(400));
    }
}
