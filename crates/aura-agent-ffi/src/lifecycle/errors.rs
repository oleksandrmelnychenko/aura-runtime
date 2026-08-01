use super::*;

thread_local! {
    pub(super) static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub(super) fn set_last_error(msg: impl Into<String>) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(msg.into());
    });
}

pub(super) fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

pub(super) fn ffi_guard<R>(default: R, body: impl FnOnce() -> R) -> R {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(payload) => {
            set_last_error(format!("panic in FFI export: {}", panic_message(&*payload)));
            default
        }
    }
}

pub(super) fn clear_last_error() {
    LAST_ERROR.with(|error| {
        error.borrow_mut().take();
    });
}
