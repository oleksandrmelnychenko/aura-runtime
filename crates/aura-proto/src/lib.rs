pub mod messenger {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/aura.messenger.v1.rs"));
    }
}
