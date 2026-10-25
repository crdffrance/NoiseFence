//! Off-path source collection. Connectors return complete candidates, never
//! publish directly, and have no mailbox-routing or console-grant authority.
pub mod aws;
pub mod entra;
pub mod google;
mod graph;
pub mod okta;
