//! Off-path source collection. Connectors return complete candidates, never
//! publish directly, and have no mailbox-routing or console-grant authority.
pub mod entra;
mod graph;
pub mod okta;
