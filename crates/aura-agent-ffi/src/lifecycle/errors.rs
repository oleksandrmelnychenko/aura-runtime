use super::*;

thread_local! {
    pub(super) static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Process-global mirror of the most recent error message.
///
/// `LAST_ERROR` (thread-local, errno-style) is the primary store, but in some
/// static-library / iOS link configurations a thread-local write is not
/// observed by a subsequent read, which surfaced on the Swift side as
/// "unknown error" even though an error message *was* set (e.g. a real
/// `aura_init` failure whose reason was silently dropped). The mirror is a
/// one-shot cross-thread fallback: reading the matching thread-local error, or
/// reading the fallback directly, consumes the global copy so a later
/// successful operation cannot observe a stale failure.
pub(super) static LAST_ERROR_GLOBAL: Mutex<Option<String>> = Mutex::new(None);

pub(super) fn set_last_error(msg: impl Into<String>) {
    let msg = msg.into();
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(msg.clone());
    });
    if let Ok(mut guard) = LAST_ERROR_GLOBAL.lock() {
        *guard = Some(msg);
    }
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
    let previous = LAST_ERROR.with(|error| error.borrow_mut().take());
    let Some(previous) = previous else {
        return;
    };
    if let Ok(mut guard) = LAST_ERROR_GLOBAL.lock() {
        if guard.as_deref() == Some(previous.as_str()) {
            *guard = None;
        }
    }
}
