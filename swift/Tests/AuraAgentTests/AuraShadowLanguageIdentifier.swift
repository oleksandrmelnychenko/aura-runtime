import CoreML
import CryptoKit
import Foundation
import NaturalLanguage

/// Content-free reason emitted by the shadow language-ID abstention boundary.
internal enum AuraShadowLanguageAbstentionReason: String, Sendable {
    case insufficientText
    case unsupportedCyrillicAlphabet
    case malformedModelOutput
    case unsupportedModelLabel
    case ngramMarginBelowFloor
    case modelDisagreement
    case coreMLProbabilityBelowFloor
    case coreMLMarginBelowFloor
    case appleLanguageDisagreement
}

internal struct AuraShadowLanguageMatch: Equatable, Sendable {
    let languageTag: String
    let coreMLProbability: Double
    let coreMLMargin: Double
    let ngramMargin: Double
}

internal enum AuraShadowLanguageDecision: Equatable, Sendable {
    case language(AuraShadowLanguageMatch)
    case abstain(AuraShadowLanguageAbstentionReason)
}

internal struct AuraShadowLanguageArtifactIdentity: Equatable, Sendable {
    let identifier: String
    let manifestSHA256Hex: String
    let artifactSHA256ByPath: [String: String]
}

internal enum AuraShadowLanguageIdentifierError: Error, Equatable {
    case resourceMissing(String)
    case manifestDigestMismatch
    case malformedManifest(String)
    case unsafeResourcePath(String)
    case artifactInventoryMismatch
    case artifactDigestMismatch(String)
    case malformedNGramModel(String)
    case coreMLLoadFailed
}

/// Shadow-only ensemble. It has no production routing or span-emission hook.
///
/// The actor serializes `NLModel` access because NaturalLanguage analyzers are
/// not documented as thread-safe. It retains model state only, never plaintext.
@available(macOS 12.0, iOS 18.0, *)
internal actor AuraShadowLanguageIdentifier {
    private static let expectedManifestSHA256Hex =
        "7bfb27d993fda7591a2414722cefcc8d3c5372638164122bede0bb5450236d5f"
    private static let manifestFilename = "manifest.json"
    private static let resourceDirectory = "LanguageID"

    private let manifest: AuraShadowLanguageManifest
    private let coreMLModel: NLModel
    private let ngramModel: AuraHashedNGramLanguageModel
    nonisolated let artifactIdentity: AuraShadowLanguageArtifactIdentity

    private init(
        manifest: AuraShadowLanguageManifest,
        coreMLModel: NLModel,
        ngramModel: AuraHashedNGramLanguageModel,
        artifactIdentity: AuraShadowLanguageArtifactIdentity
    ) {
        self.manifest = manifest
        self.coreMLModel = coreMLModel
        self.ngramModel = ngramModel
        self.artifactIdentity = artifactIdentity
    }

    internal static func loadBundled(
        computeUnits: MLComputeUnits = .all
    ) async throws -> AuraShadowLanguageIdentifier {
        let resourceRoot = try bundledResourceRoot()

        let validated = try AuraShadowLanguageBundleValidator.validate(
            resourceRoot: resourceRoot,
            expectedManifestSHA256Hex: expectedManifestSHA256Hex
        )
        let ngramURL = resourceRoot.appendingPathComponent(validated.manifest.ngramFilename)
        let ngramData = try Data(contentsOf: ngramURL, options: [.mappedIfSafe])
        let ngramModel = try AuraHashedNGramLanguageModel(data: ngramData)

        let configuration = MLModelConfiguration()
        configuration.computeUnits = computeUnits
        let modelURL = resourceRoot.appendingPathComponent(
            validated.manifest.modelDirectory,
            isDirectory: true
        )
        let loadedModel: MLModel
        do {
            loadedModel = try await MLModel.load(
                contentsOf: modelURL,
                configuration: configuration
            )
        } catch {
            throw AuraShadowLanguageIdentifierError.coreMLLoadFailed
        }
        let naturalLanguageModel: NLModel
        do {
            naturalLanguageModel = try NLModel(mlModel: loadedModel)
        } catch {
            throw AuraShadowLanguageIdentifierError.coreMLLoadFailed
        }

        return AuraShadowLanguageIdentifier(
            manifest: validated.manifest,
            coreMLModel: naturalLanguageModel,
            ngramModel: ngramModel,
            artifactIdentity: validated.identity
        )
    }

    #if DEBUG
    internal static func validateBundledArtifactsForTesting(
        expectedManifestSHA256Hex: String
    ) throws -> AuraShadowLanguageArtifactIdentity {
        try AuraShadowLanguageBundleValidator.validate(
            resourceRoot: bundledResourceRoot(),
            expectedManifestSHA256Hex: expectedManifestSHA256Hex
        ).identity
    }
    #endif

    internal func classify(_ text: String) -> AuraShadowLanguageDecision {
        let boundedText = Self.boundedText(
            text,
            maximumUTF8Bytes: manifest.policy.maximumUTF8Bytes
        )
        guard Self.alphabeticScalarCount(boundedText)
            >= manifest.policy.minimumAlphabeticScalars
        else {
            return .abstain(.insufficientText)
        }

        let allowedCyrillic = Set(manifest.policy.allowedCyrillicScalars.unicodeScalars)
        if boundedText.lowercased().unicodeScalars.contains(where: { scalar in
            (0x0400 ... 0x052F).contains(scalar.value) && !allowedCyrillic.contains(scalar)
        }) {
            return .abstain(.unsupportedCyrillicAlphabet)
        }

        guard let ngram = ngramModel.classify(boundedText) else {
            return .abstain(.malformedModelOutput)
        }
        guard manifest.governedLabels.contains(ngram.label) else {
            return .abstain(.unsupportedModelLabel)
        }
        guard ngram.margin >= manifest.policy.minimumNgramMargin else {
            return .abstain(.ngramMarginBelowFloor)
        }

        let hypotheses = coreMLModel.predictedLabelHypotheses(
            for: boundedText,
            maximumCount: manifest.labels.count
        )
        guard let coreML = Self.validatedCoreMLResult(
            hypotheses,
            expectedLabels: manifest.labels
        ) else {
            return .abstain(.malformedModelOutput)
        }
        guard manifest.governedLabels.contains(coreML.label) else {
            return .abstain(.unsupportedModelLabel)
        }
        guard coreML.label == ngram.label else {
            return .abstain(.modelDisagreement)
        }
        guard coreML.probability >= manifest.policy.minimumCoreMLProbability else {
            return .abstain(.coreMLProbabilityBelowFloor)
        }
        guard coreML.margin >= manifest.policy.minimumCoreMLMargin else {
            return .abstain(.coreMLMarginBelowFloor)
        }

        if manifest.policy.requireAppleLanguageAgreement {
            let appleLanguage = NLLanguageRecognizer.dominantLanguage(for: boundedText)?.rawValue
            guard appleLanguage == coreML.label else {
                return .abstain(.appleLanguageDisagreement)
            }
        }

        return .language(
            AuraShadowLanguageMatch(
                languageTag: coreML.label,
                coreMLProbability: coreML.probability,
                coreMLMargin: coreML.margin,
                ngramMargin: ngram.margin
            )
        )
    }

    private static func validatedCoreMLResult(
        _ hypotheses: [String: Double],
        expectedLabels: [String]
    ) -> (label: String, probability: Double, margin: Double)? {
        guard Set(hypotheses.keys) == Set(expectedLabels),
              hypotheses.values.allSatisfy({ $0.isFinite && (0 ... 1).contains($0) })
        else {
            return nil
        }
        let probabilitySum = hypotheses.values.reduce(0, +)
        guard (0.999 ... 1.001).contains(probabilitySum) else {
            return nil
        }
        let ordered = hypotheses.sorted {
            if $0.value == $1.value {
                return $0.key < $1.key
            }
            return $0.value > $1.value
        }
        guard let first = ordered.first else {
            return nil
        }
        let secondProbability = ordered.dropFirst().first?.value ?? 0
        return (first.key, first.value, first.value - secondProbability)
    }

    private static func boundedText(_ text: String, maximumUTF8Bytes: Int) -> String {
        guard text.utf8.count > maximumUTF8Bytes else {
            return text
        }
        var byteCount = 0
        var endIndex = text.startIndex
        while endIndex < text.endIndex {
            let nextIndex = text.index(after: endIndex)
            let nextBytes = text[endIndex ..< nextIndex].utf8.count
            guard byteCount + nextBytes <= maximumUTF8Bytes else {
                break
            }
            byteCount += nextBytes
            endIndex = nextIndex
        }
        return String(text[..<endIndex])
    }

    private static func alphabeticScalarCount(_ text: String) -> Int {
        text.unicodeScalars.reduce(into: 0) { count, scalar in
            if scalar.properties.isAlphabetic {
                count += 1
            }
        }
    }

    private static func bundledResourceRoot() throws -> URL {
        guard let resourceRoot = Bundle.module.resourceURL?
            .appendingPathComponent(resourceDirectory, isDirectory: true),
            FileManager.default.fileExists(atPath: resourceRoot.path)
        else {
            throw AuraShadowLanguageIdentifierError.resourceMissing(resourceDirectory)
        }
        return resourceRoot
    }
}

private struct AuraShadowLanguageManifest: Decodable, Sendable {
    let schemaVersion: Int
    let identifier: String
    let releaseState: String
    let productionSpanEmissionEnabled: Bool
    let modelDirectory: String
    let ngramFilename: String
    let labels: [String]
    let governedLabels: [String]
    let unsupportedLabels: [String]
    let policy: Policy
    let artifacts: [Artifact]
    let provenance: Provenance

    struct Policy: Decodable, Sendable {
        let minimumAlphabeticScalars: Int
        let maximumUtf8Bytes: Int
        let minimumCoremlProbability: Double
        let minimumCoremlMargin: Double
        let minimumNgramMargin: Double
        let requireAppleLanguageAgreement: Bool
        let allowedCyrillicScalars: String

        var minimumCoreMLProbability: Double { minimumCoremlProbability }
        var minimumCoreMLMargin: Double { minimumCoremlMargin }
        var maximumUTF8Bytes: Int { maximumUtf8Bytes }
    }

    struct Artifact: Decodable, Sendable {
        let path: String
        let sha256: String
    }

    struct Provenance: Decodable, Sendable {
        let sourceDataset: String
        let sourceModelSha256: String
        let sourceSummarySha256: String
        let coremlTrainingMetricsSha256: String
        let ngramTrainingMetricsSha256: String
        let xcode: String
        let releaseEligible: Bool
    }
}

@available(macOS 12.0, iOS 18.0, *)
private enum AuraShadowLanguageBundleValidator {
    private static let maximumManifestBytes = 64 * 1024
    private static let expectedTopLevelKeys: Set<String> = [
        "schema_version", "identifier", "release_state",
        "production_span_emission_enabled", "model_directory", "ngram_filename",
        "labels", "governed_labels", "unsupported_labels", "policy", "artifacts",
        "provenance",
    ]
    private static let expectedPolicyKeys: Set<String> = [
        "minimum_alphabetic_scalars", "maximum_utf8_bytes",
        "minimum_coreml_probability", "minimum_coreml_margin",
        "minimum_ngram_margin", "require_apple_language_agreement",
        "allowed_cyrillic_scalars",
    ]
    private static let expectedProvenanceKeys: Set<String> = [
        "source_dataset", "source_model_sha256", "source_summary_sha256",
        "coreml_training_metrics_sha256", "ngram_training_metrics_sha256",
        "xcode", "release_eligible",
    ]
    private static let expectedArtifactKeys: Set<String> = ["path", "sha256"]
    private static let expectedArtifactPaths: Set<String> = [
        "AuraAbstainingLanguageID.mlmodelc/analytics/coremldata.bin",
        "AuraAbstainingLanguageID.mlmodelc/coremldata.bin",
        "AuraAbstainingLanguageID.mlmodelc/metadata.json",
        "AuraLanguageIDNGramV1.bin",
    ]

    struct ValidatedBundle {
        let manifest: AuraShadowLanguageManifest
        let identity: AuraShadowLanguageArtifactIdentity
    }

    static func validate(
        resourceRoot: URL,
        expectedManifestSHA256Hex: String
    ) throws -> ValidatedBundle {
        let manifestURL = resourceRoot.appendingPathComponent("manifest.json")
        let manifestData = try safeFileData(
            at: manifestURL,
            root: resourceRoot,
            maximumBytes: maximumManifestBytes
        )
        guard sha256Hex(manifestData) == expectedManifestSHA256Hex else {
            throw AuraShadowLanguageIdentifierError.manifestDigestMismatch
        }
        try validateStrictJSONShape(manifestData)

        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let manifest: AuraShadowLanguageManifest
        do {
            manifest = try decoder.decode(AuraShadowLanguageManifest.self, from: manifestData)
        } catch {
            throw AuraShadowLanguageIdentifierError.malformedManifest("decode")
        }
        try validateManifestValues(manifest)

        let inventory = try regularFileInventory(root: resourceRoot)
        guard inventory == expectedArtifactPaths.union(["manifest.json"]) else {
            throw AuraShadowLanguageIdentifierError.artifactInventoryMismatch
        }

        var artifactDigests: [String: String] = [:]
        for artifact in manifest.artifacts {
            let url = resourceRoot.appendingPathComponent(artifact.path)
            let data = try safeFileData(
                at: url,
                root: resourceRoot,
                maximumBytes: 4 * 1024 * 1024
            )
            let digest = sha256Hex(data)
            guard digest == artifact.sha256 else {
                throw AuraShadowLanguageIdentifierError.artifactDigestMismatch(artifact.path)
            }
            artifactDigests[artifact.path] = digest
        }

        return ValidatedBundle(
            manifest: manifest,
            identity: AuraShadowLanguageArtifactIdentity(
                identifier: manifest.identifier,
                manifestSHA256Hex: expectedManifestSHA256Hex,
                artifactSHA256ByPath: artifactDigests
            )
        )
    }

    private static func validateStrictJSONShape(_ data: Data) throws {
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw AuraShadowLanguageIdentifierError.malformedManifest("json")
        }
        guard let root = object as? [String: Any], Set(root.keys) == expectedTopLevelKeys,
              let policy = root["policy"] as? [String: Any],
              Set(policy.keys) == expectedPolicyKeys,
              let provenance = root["provenance"] as? [String: Any],
              Set(provenance.keys) == expectedProvenanceKeys,
              let artifacts = root["artifacts"] as? [[String: Any]],
              artifacts.allSatisfy({ Set($0.keys) == expectedArtifactKeys })
        else {
            throw AuraShadowLanguageIdentifierError.malformedManifest("shape")
        }
    }

    private static func validateManifestValues(
        _ manifest: AuraShadowLanguageManifest
    ) throws {
        guard manifest.schemaVersion == 1,
              manifest.identifier == "aura-language-id-shadow-maxent-ngram-v1",
              manifest.releaseState == "shadow_only",
              !manifest.productionSpanEmissionEnabled,
              manifest.modelDirectory == "AuraAbstainingLanguageID.mlmodelc",
              manifest.ngramFilename == "AuraLanguageIDNGramV1.bin",
              manifest.labels == ["en", "ru", "tt", "uk"],
              manifest.governedLabels == ["en", "ru", "uk"],
              manifest.unsupportedLabels == ["tt"],
              manifest.policy.minimumAlphabeticScalars == 20,
              manifest.policy.maximumUTF8Bytes == 10_000,
              manifest.policy.minimumCoreMLProbability == 0.50,
              manifest.policy.minimumCoreMLMargin == 0.20,
              manifest.policy.minimumNgramMargin == 0.20,
              manifest.policy.requireAppleLanguageAgreement,
              manifest.policy.allowedCyrillicScalars
                  == "абвгґдеёєжзиіїйклмнопрстуфхцчшщъыьэюя",
              !manifest.provenance.releaseEligible,
              !manifest.provenance.sourceDataset.isEmpty,
              !manifest.provenance.xcode.isEmpty,
              isLowercaseSHA256(manifest.provenance.sourceModelSha256),
              isLowercaseSHA256(manifest.provenance.sourceSummarySha256),
              isLowercaseSHA256(manifest.provenance.coremlTrainingMetricsSha256),
              isLowercaseSHA256(manifest.provenance.ngramTrainingMetricsSha256),
              manifest.artifacts.map(\.path).sorted() == Array(expectedArtifactPaths).sorted(),
              Set(manifest.artifacts.map(\.path)).count == manifest.artifacts.count,
              manifest.artifacts.allSatisfy({ isLowercaseSHA256($0.sha256) })
        else {
            throw AuraShadowLanguageIdentifierError.malformedManifest("values")
        }
    }

    private static func safeFileData(
        at url: URL,
        root: URL,
        maximumBytes: Int
    ) throws -> Data {
        let rootPath = root.standardizedFileURL.resolvingSymlinksInPath().path
        let resolvedURL = url.standardizedFileURL.resolvingSymlinksInPath()
        guard resolvedURL.path.hasPrefix(rootPath + "/") else {
            throw AuraShadowLanguageIdentifierError.unsafeResourcePath("outside-root")
        }
        let values = try url.resourceValues(forKeys: [
            .isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey,
        ])
        guard values.isRegularFile == true, values.isSymbolicLink != true else {
            throw AuraShadowLanguageIdentifierError.unsafeResourcePath("not-regular")
        }
        guard let fileSize = values.fileSize,
              (0 ... maximumBytes).contains(fileSize)
        else {
            throw AuraShadowLanguageIdentifierError.unsafeResourcePath("size")
        }
        return try Data(contentsOf: url, options: [.mappedIfSafe])
    }

    private static func regularFileInventory(root: URL) throws -> Set<String> {
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
            options: [.skipsHiddenFiles]
        ) else {
            throw AuraShadowLanguageIdentifierError.artifactInventoryMismatch
        }
        var inventory: Set<String> = []
        let resolvedRootPath = root.standardizedFileURL.resolvingSymlinksInPath().path
        for case let url as URL in enumerator {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            let resolvedURL = url.standardizedFileURL.resolvingSymlinksInPath()
            guard resolvedURL.path.hasPrefix(resolvedRootPath + "/") else {
                throw AuraShadowLanguageIdentifierError.unsafeResourcePath("inventory-outside-root")
            }
            if values.isRegularFile == true {
                let prefix = resolvedRootPath + "/"
                inventory.insert(String(resolvedURL.path.dropFirst(prefix.count)))
            }
        }
        return inventory
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func isLowercaseSHA256(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy {
            (0x30 ... 0x39).contains($0) || (0x61 ... 0x66).contains($0)
        } && value.contains(where: { $0 != "0" })
    }
}

private struct AuraHashedNGramLanguageModel: Sendable {
    private static let magic = Data("AURALID1".utf8)
    private static let expectedLabels = ["en", "uk", "ru", "tt"]
    private static let expectedBucketCount = 16_384
    private static let expectedMinimumNgram = 2
    private static let expectedMaximumNgram = 5
    private static let expectedAlpha = 0.05
    private static let fnvOffsetBasis: UInt64 = 14_695_981_039_346_656_037
    private static let fnvPrime: UInt64 = 1_099_511_628_211

    private let labels: [String]
    private let bucketCount: Int
    private let minimumNgram: Int
    private let maximumNgram: Int
    private let logProbabilities: [Float]

    init(data: Data) throws {
        var reader = AuraBinaryReader(data: data)
        guard try reader.readData(count: Self.magic.count) == Self.magic else {
            throw AuraShadowLanguageIdentifierError.malformedNGramModel("magic")
        }
        let version = try reader.readUInt32()
        let bucketCount = Int(try reader.readUInt32())
        let minimumNgram = Int(try reader.readUInt32())
        let maximumNgram = Int(try reader.readUInt32())
        let alpha = try reader.readDouble()
        let labelCount = Int(try reader.readUInt32())
        guard version == 1,
              bucketCount == Self.expectedBucketCount,
              minimumNgram == Self.expectedMinimumNgram,
              maximumNgram == Self.expectedMaximumNgram,
              alpha == Self.expectedAlpha,
              labelCount == Self.expectedLabels.count
        else {
            throw AuraShadowLanguageIdentifierError.malformedNGramModel("header")
        }

        var labels: [String] = []
        var probabilities: [Float] = []
        probabilities.reserveCapacity(bucketCount * labelCount)
        for _ in 0 ..< labelCount {
            let labelLength = Int(try reader.readUInt8())
            let labelData = try reader.readData(count: labelLength)
            guard let label = String(data: labelData, encoding: .ascii),
                  (2 ... 8).contains(label.utf8.count),
                  try reader.readUInt64() > 0
            else {
                throw AuraShadowLanguageIdentifierError.malformedNGramModel("label")
            }
            labels.append(label)
            for _ in 0 ..< bucketCount {
                let value = try reader.readFloat()
                guard value.isFinite, value < 0, value > -100 else {
                    throw AuraShadowLanguageIdentifierError.malformedNGramModel("weight")
                }
                probabilities.append(value)
            }
        }
        guard labels == Self.expectedLabels, reader.isAtEnd else {
            throw AuraShadowLanguageIdentifierError.malformedNGramModel("layout")
        }

        self.labels = labels
        self.bucketCount = bucketCount
        self.minimumNgram = minimumNgram
        self.maximumNgram = maximumNgram
        logProbabilities = probabilities
    }

    func classify(_ text: String) -> (label: String, margin: Double)? {
        let features = featureCounts(text)
        let total = features.values.reduce(0, +)
        guard total > 0 else {
            return nil
        }
        var scores: [(label: String, score: Double)] = []
        scores.reserveCapacity(labels.count)
        for labelIndex in labels.indices {
            let rowOffset = labelIndex * bucketCount
            let accumulated = features.reduce(into: 0.0) { score, entry in
                score += Double(entry.value)
                    * Double(logProbabilities[rowOffset + entry.key])
            }
            scores.append((labels[labelIndex], accumulated / Double(total)))
        }
        scores.sort {
            if $0.score == $1.score {
                return $0.label < $1.label
            }
            return $0.score > $1.score
        }
        guard let first = scores.first else {
            return nil
        }
        return (first.label, first.score - (scores.dropFirst().first?.score ?? first.score))
    }

    private func featureCounts(_ text: String) -> [Int: Int] {
        let normalized = text
            .precomposedStringWithCompatibilityMapping
            .lowercased(with: Locale(identifier: "en_US_POSIX"))
        var scalars: [Unicode.Scalar] = ["^"]
        var pendingSpace = false
        for scalar in normalized.unicodeScalars {
            if scalar.properties.isAlphabetic {
                if pendingSpace, scalars.count > 1 {
                    scalars.append(" ")
                }
                scalars.append(scalar)
                pendingSpace = false
            } else if scalars.count > 1 {
                pendingSpace = true
            }
        }
        if scalars.last == " " {
            scalars.removeLast()
        }
        scalars.append("$")

        var counts: [Int: Int] = [:]
        for width in minimumNgram ... maximumNgram where scalars.count >= width {
            for start in 0 ... (scalars.count - width) {
                var hash = Self.fnvOffsetBasis
                for scalar in scalars[start ..< start + width] {
                    Self.updateFNV(&hash, scalar: scalar)
                }
                counts[Int(hash % UInt64(bucketCount)), default: 0] += 1
            }
        }
        return counts
    }

    private static func updateFNV(_ hash: inout UInt64, scalar: Unicode.Scalar) {
        let value = scalar.value
        if value <= 0x7F {
            updateFNV(&hash, byte: UInt8(value))
        } else if value <= 0x7FF {
            updateFNV(&hash, byte: UInt8(0xC0 | (value >> 6)))
            updateFNV(&hash, byte: UInt8(0x80 | (value & 0x3F)))
        } else if value <= 0xFFFF {
            updateFNV(&hash, byte: UInt8(0xE0 | (value >> 12)))
            updateFNV(&hash, byte: UInt8(0x80 | ((value >> 6) & 0x3F)))
            updateFNV(&hash, byte: UInt8(0x80 | (value & 0x3F)))
        } else {
            updateFNV(&hash, byte: UInt8(0xF0 | (value >> 18)))
            updateFNV(&hash, byte: UInt8(0x80 | ((value >> 12) & 0x3F)))
            updateFNV(&hash, byte: UInt8(0x80 | ((value >> 6) & 0x3F)))
            updateFNV(&hash, byte: UInt8(0x80 | (value & 0x3F)))
        }
    }

    private static func updateFNV(_ hash: inout UInt64, byte: UInt8) {
        hash = (hash ^ UInt64(byte)) &* fnvPrime
    }
}

private struct AuraBinaryReader {
    private let data: Data
    private(set) var offset = 0

    init(data: Data) {
        self.data = data
    }

    var isAtEnd: Bool { offset == data.count }

    mutating func readData(count: Int) throws -> Data {
        guard count >= 0, offset <= data.count - count else {
            throw AuraShadowLanguageIdentifierError.malformedNGramModel("truncated")
        }
        defer { offset += count }
        return data[offset ..< offset + count]
    }

    mutating func readUInt8() throws -> UInt8 {
        try readInteger(byteCount: 1)
    }

    mutating func readUInt32() throws -> UInt32 {
        try readInteger(byteCount: 4)
    }

    mutating func readUInt64() throws -> UInt64 {
        try readInteger(byteCount: 8)
    }

    mutating func readFloat() throws -> Float {
        Float(bitPattern: try readUInt32())
    }

    mutating func readDouble() throws -> Double {
        Double(bitPattern: try readUInt64())
    }

    private mutating func readInteger<T: FixedWidthInteger>(
        byteCount: Int
    ) throws -> T {
        guard byteCount == MemoryLayout<T>.size,
              offset <= data.count - byteCount
        else {
            throw AuraShadowLanguageIdentifierError.malformedNGramModel("truncated")
        }
        var result: T = 0
        for shift in 0 ..< byteCount {
            result |= T(data[offset + shift]) << T(shift * 8)
        }
        offset += byteCount
        return result
    }
}
