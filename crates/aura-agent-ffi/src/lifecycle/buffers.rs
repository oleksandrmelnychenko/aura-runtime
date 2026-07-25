use super::*;

#[repr(C)]
/// Opaque byte buffer returned by FFI calls for protobuf-encoded responses.
pub struct AuraBuffer {
    /// Pointer to the allocated byte data.
    pub ptr: *mut u8,
    /// Length of the byte data in bytes.
    pub len: usize,
}

impl AuraBuffer {
    pub(super) fn empty() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }
}

pub(super) fn prepare_output(out: *mut AuraBuffer) -> Result<(), String> {
    if out.is_null() {
        return Err("null out pointer".to_string());
    }
    unsafe {
        *out = AuraBuffer::empty();
    }
    Ok(())
}

pub(super) unsafe fn decode_proto_bounded<M>(
    ptr: *const u8,
    len: usize,
    label: &str,
    max_len: usize,
) -> Result<M, String>
where
    M: ProstMessage + Default,
{
    if ptr.is_null() {
        return Err(format!("null {label} pointer"));
    }
    if len > max_len {
        return Err(format!("{label} exceeds limit of {max_len} bytes"));
    }

    M::decode(std::slice::from_raw_parts(ptr, len))
        .map_err(|e| format!("invalid protobuf in {label}: {e}"))
}

pub(super) fn write_proto_message<M>(out: *mut AuraBuffer, message: &M) -> Result<(), String>
where
    M: ProstMessage,
{
    let mut bytes = Vec::with_capacity(message.encoded_len());
    message
        .encode(&mut bytes)
        .map_err(|e| format!("failed to encode protobuf response: {e}"))?;

    unsafe {
        *out = bytes_to_buffer(bytes);
    }
    Ok(())
}

pub(super) fn bytes_to_buffer(bytes: Vec<u8>) -> AuraBuffer {
    let mut bytes = bytes.into_boxed_slice();
    let ptr = bytes.as_mut_ptr();
    let len = bytes.len();
    std::mem::forget(bytes);
    AuraBuffer { ptr, len }
}
