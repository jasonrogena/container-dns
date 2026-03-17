use std::{collections::HashMap, rc::Rc};

use crate::containers::Container;

/// Returns a map of pid → (priority, weight) for the given containers.
///
/// Containers are sorted by 1-minute load average ascending so the least-loaded
/// container receives priority 0 (highest preference per RFC 2782). Ties are
/// broken by PID for determinism. Containers whose load average is unavailable
/// are treated as fully idle (load = 0.0) and sorted ahead of loaded containers
/// with the same explicit load, using PID as the tiebreaker.
///
/// Weight is an absolute scalar derived from load so values are meaningful when
/// compared across hosts: weight = clamp(100 / (1 + load_avg), 1, 100).
pub fn priorities_and_weights(containers: &[Rc<dyn Container>]) -> HashMap<u32, (u16, u16)> {
    let mut loads: Vec<(u32, f64)> = containers
        .iter()
        .map(|c| (c.pid(), c.load_average().unwrap_or(0.0)))
        .collect();

    loads.sort_by(|a, b| {
        a.1.partial_cmp(&b.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });

    loads
        .iter()
        .enumerate()
        .map(|(priority, (pid, load))| {
            let weight = (100.0 / (1.0 + load)).clamp(1.0, 100.0) as u16;
            (*pid, (priority as u16, weight))
        })
        .collect()
}
