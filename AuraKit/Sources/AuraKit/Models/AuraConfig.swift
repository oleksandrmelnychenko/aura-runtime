import Foundation

public struct AuraConfig: Encodable, Sendable {
    public var protectionLevel: ProtectionLevel
    public var accountType: AccountType
    public var language: String
    public var culturalContext: String
    public var enabled: Bool
    public var patternsPath: String?
    public var modelsPath: String?
    public var accountHolderAge: UInt16?
    public var ttlDays: UInt32

    enum CodingKeys: String, CodingKey {
        case protectionLevel = "protection_level"
        case accountType = "account_type"
        case language
        case culturalContext = "cultural_context"
        case enabled
        case patternsPath = "patterns_path"
        case modelsPath = "models_path"
        case accountHolderAge = "account_holder_age"
        case ttlDays = "ttl_days"
    }

    public init(
        protectionLevel: ProtectionLevel = .medium,
        accountType: AccountType = .adult,
        language: String = "uk",
        culturalContext: String = "ukrainian",
        enabled: Bool = true,
        patternsPath: String? = nil,
        modelsPath: String? = nil,
        accountHolderAge: UInt16? = nil,
        ttlDays: UInt32 = 30
    ) {
        self.protectionLevel = protectionLevel
        self.accountType = accountType
        self.language = language
        self.culturalContext = culturalContext
        self.enabled = enabled
        self.patternsPath = patternsPath
        self.modelsPath = modelsPath
        self.accountHolderAge = accountHolderAge
        self.ttlDays = ttlDays
    }
}
