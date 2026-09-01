#!/usr/bin/env xcrun swift

import CoreML
import CreateML
import CryptoKit
import Foundation
import TabularData

private func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("error: \(message)\n".utf8))
    Foundation.exit(2)
}

private func sha256Hex(_ url: URL) throws -> String {
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

guard CommandLine.arguments.count == 4 else {
    fail("usage: train_coreml_language_id.swift INPUT_DIR OUTPUT_MODEL OUTPUT_METRICS")
}

let inputDirectory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
let outputModel = URL(fileURLWithPath: CommandLine.arguments[2])
let outputMetrics = URL(fileURLWithPath: CommandLine.arguments[3])

do {
    let trainURL = inputDirectory.appendingPathComponent("train.csv")
    let calibrationURL = inputDirectory.appendingPathComponent("calibration.csv")
    let testURL = inputDirectory.appendingPathComponent("test.csv")
    let train = try DataFrame(contentsOfCSVFile: trainURL)
    let calibration = try DataFrame(contentsOfCSVFile: calibrationURL)
    let test = try DataFrame(contentsOfCSVFile: testURL)

    var parameters = MLTextClassifier.ModelParameters(
        validation: .none,
        algorithm: .maxEnt(revision: 1),
        language: nil
    )
    parameters.maxIterations = 25
    let classifier = try MLTextClassifier(
        trainingData: train,
        textColumn: "text",
        labelColumn: "label",
        parameters: parameters
    )

    let calibrationMetrics = classifier.evaluation(
        on: calibration,
        textColumn: "text",
        labelColumn: "label"
    )
    let testMetrics = classifier.evaluation(
        on: test,
        textColumn: "text",
        labelColumn: "label"
    )
    try classifier.write(
        to: outputModel,
        metadata: MLModelMetadata(
            author: "Aura",
            shortDescription: "Development shadow language identifier; release use requires governed manifest and approval",
            version: "1.0"
        )
    )

    let metrics: [String: Any] = [
        "schema_version": 1,
        "algorithm": "Create ML MLTextClassifier maxEnt revision 1",
        "labels": ["en", "ru", "tt", "uk"],
        "training_rows": train.rows.count,
        "calibration_rows": calibration.rows.count,
        "test_rows": test.rows.count,
        "training_classification_error": classifier.trainingMetrics.classificationError,
        "calibration_classification_error": calibrationMetrics.classificationError,
        "test_classification_error": testMetrics.classificationError,
        "training_csv_sha256": try sha256Hex(trainURL),
        "model_sha256": try sha256Hex(outputModel),
        "release_eligible": false,
    ]
    let encoded = try JSONSerialization.data(
        withJSONObject: metrics,
        options: [.prettyPrinted, .sortedKeys]
    )
    var output = encoded
    output.append(0x0A)
    try output.write(to: outputMetrics, options: .atomic)
    print("model: \(outputModel.path)")
    print("metrics: \(outputMetrics.path)")
} catch {
    fail(String(describing: error))
}
