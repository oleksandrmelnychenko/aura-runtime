import AuraFFI
import Foundation

enum FFIBridge {

    /// Call an FFI function that returns a C string, copy to Swift String,
    /// and free the C string. Returns nil if the pointer was null.
    static func consumeCString(_ ptr: UnsafeMutablePointer<CChar>?) -> String? {
        guard let ptr = ptr else { return nil }
        let string = String(cString: ptr)
        aura_free_string(ptr)
        return string
    }

    /// Encode a Codable value to JSON and pass as a C string to the given closure.
    static func withJSONCString<T: Encodable, R>(
        _ value: T,
        body: (UnsafePointer<CChar>) throws -> R
    ) throws -> R {
        let encoder = JSONEncoder()
        let data = try encoder.encode(value)
        guard let jsonString = String(data: data, encoding: .utf8) else {
            throw AuraError.invalidJSON("failed to encode to UTF-8")
        }
        return try jsonString.withCString(body)
    }

    /// Decode a JSON string from FFI into a Swift Decodable type.
    /// Checks for FFI-level error JSON first.
    static func decodeResult<T: Decodable>(_ jsonString: String) throws -> T {
        let data = Data(jsonString.utf8)

        // Check if it's an error response from Rust
        if let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let isError = dict["error"] as? Bool, isError
        {
            let code = dict["code"] as? Int ?? 0
            let message = dict["message"] as? String ?? "unknown error"
            throw AuraError.ffiError(code: code, message: message)
        }

        let decoder = JSONDecoder()
        return try decoder.decode(T.self, from: data)
    }
}
