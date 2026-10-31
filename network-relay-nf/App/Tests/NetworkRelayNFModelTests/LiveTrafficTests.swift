import Foundation
import XCTest
@testable import NetworkRelayNFModel

final class LiveTrafficTests: XCTestCase {
    private func snapshot(_ up: UInt64, _ down: UInt64, _ nanos: UInt64) -> TrafficSnapshot {
        TrafficSnapshot(uploadBytes: up, downloadBytes: down, elapsedNanoseconds: nanos)
    }

    func testOneSecondWindowsUseActualElapsedTimeAndBecomeIdle() {
        var traffic = LiveTraffic()
        traffic.sample(snapshot(100, 200, 0))
        traffic.sample(snapshot(500, 1000, 400_000_000))
        XCTAssertEqual(traffic.state, .idle)
        traffic.sample(snapshot(1600, 3200, 1_500_000_000))
        XCTAssertEqual(traffic.uploadBytesPerSecond, 1000)
        XCTAssertEqual(traffic.downloadBytesPerSecond, 2000)
        XCTAssertEqual(traffic.state, .active)
        traffic.sample(snapshot(1600, 3200, 2_500_000_000))
        XCTAssertEqual(traffic.state, .idle)
        XCTAssertEqual(traffic.uploadBytesPerSecond, 0)
    }

    func testResetCounterRollbackAndLongGapsEstablishNewBaselines() {
        for changed in [snapshot(0, 0, 2_000_000_000), snapshot(1_000_000, 1_000_000, 5_000_000_001),
                        snapshot(100, 100, 1_000_000_000)] {
            var traffic = LiveTraffic()
            traffic.sample(snapshot(0, 0, 0))
            traffic.sample(snapshot(1000, 2000, 1_000_000_000))
            traffic.sample(changed)
            XCTAssertEqual(traffic.state, .idle)
            XCTAssertEqual(traffic.uploadBytesPerSecond, 0)
            traffic.sample(snapshot(changed.uploadBytes + 100, changed.downloadBytes + 200,
                                    changed.elapsedNanoseconds + 1_000_000_000))
            XCTAssertEqual(traffic.uploadBytesPerSecond, 100)
            XCTAssertEqual(traffic.downloadBytesPerSecond, 200)
        }
    }

    func testTelemetryFailureAndNewRunNeverReuseOldRates() {
        var traffic = LiveTraffic()
        traffic.sample(snapshot(0, 0, 0))
        traffic.sample(snapshot(1000, 2000, 1_000_000_000))
        traffic.unavailable()
        XCTAssertEqual(traffic.state, .unavailable)
        XCTAssertEqual(traffic.downloadBytesPerSecond, 0)
        traffic.sample(snapshot(10_000, 20_000, 5_000_000_000))
        XCTAssertEqual(traffic.state, .idle)
        traffic.reset()
        XCTAssertEqual(traffic, LiveTraffic())
    }

    func testBinaryFormattingClampsInvalidAndOversizedValues() {
        XCTAssertEqual(formattedTrafficRate(1024), ByteCountFormatter.string(fromByteCount: 1024, countStyle: .binary) + "/s")
        for rate in [-1.0, Double.nan, Double.infinity] {
            XCTAssertEqual(formattedTrafficRate(rate), ByteCountFormatter.string(fromByteCount: 0, countStyle: .binary) + "/s")
        }
        XCTAssertEqual(formattedTrafficRate(Double.greatestFiniteMagnitude),
                       ByteCountFormatter.string(fromByteCount: Int64.max, countStyle: .binary) + "/s")
    }

    func testTelemetryTimestampUsesAllEightLittleEndianBytes() {
        let timestamp: UInt64 = 86_400_000_000_000
        let data = Data((0..<8).map { UInt8(truncatingIfNeeded: timestamp >> ($0 * 8)) })
        let sample = TrafficSnapshot(uploadBytes: 1024, downloadBytes: 2048, elapsedData: data)
        XCTAssertEqual(sample, snapshot(1024, 2048, timestamp))
        XCTAssertNil(TrafficSnapshot(uploadBytes: 0, downloadBytes: 0, elapsedData: Data()))
        XCTAssertNil(TrafficSnapshot(uploadBytes: 0, downloadBytes: 0, elapsedData: Data(repeating: 0, count: 9)))
    }

    func testOneSecondTimerJitterDoesNotDelayDisplayForAnotherSecond() {
        var traffic = LiveTraffic()
        traffic.sample(snapshot(0, 0, 0))
        traffic.sample(snapshot(999, 1998, 999_000_000))
        XCTAssertEqual(traffic.state, .active)
        XCTAssertEqual(traffic.uploadBytesPerSecond, 1000)
        XCTAssertEqual(traffic.downloadBytesPerSecond, 2000)
    }
}
