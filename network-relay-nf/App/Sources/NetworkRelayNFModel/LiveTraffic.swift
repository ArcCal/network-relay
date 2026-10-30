import Foundation

public struct TrafficSnapshot: Equatable {
    public let uploadBytes: UInt64
    public let downloadBytes: UInt64
    public let elapsedNanoseconds: UInt64

    public init(uploadBytes: UInt64, downloadBytes: UInt64, elapsedNanoseconds: UInt64) {
        self.uploadBytes = uploadBytes
        self.downloadBytes = downloadBytes
        self.elapsedNanoseconds = elapsedNanoseconds
    }

    public init?(uploadBytes: UInt64, downloadBytes: UInt64, elapsedData: Data) {
        guard elapsedData.count == 8 else { return nil }
        let elapsed = elapsedData.withUnsafeBytes { UInt64(littleEndian: $0.loadUnaligned(as: UInt64.self)) }
        self.init(uploadBytes: uploadBytes, downloadBytes: downloadBytes, elapsedNanoseconds: elapsed)
    }
}

/// Rates belong to one client run and use the producer's monotonic clock.
public struct LiveTraffic: Equatable {
    public enum State: Equatable { case idle, active, unavailable }
    public private(set) var state: State = .idle
    public private(set) var uploadBytesPerSecond: Double = 0
    public private(set) var downloadBytesPerSecond: Double = 0
    private var previous: TrafficSnapshot?
    private var window: TrafficSnapshot?

    public init() {}

    public mutating func reset() { self = LiveTraffic() }

    public mutating func unavailable() {
        reset()
        state = .unavailable
    }

    public mutating func sample(_ next: TrafficSnapshot) {
        guard let previous, let window,
              next.elapsedNanoseconds > previous.elapsedNanoseconds,
              next.elapsedNanoseconds - previous.elapsedNanoseconds <= 3_000_000_000,
              next.uploadBytes >= previous.uploadBytes,
              next.downloadBytes >= previous.downloadBytes else {
            reset()
            self.previous = next
            self.window = next
            return
        }
        self.previous = next
        let elapsed = next.elapsedNanoseconds - window.elapsedNanoseconds
        guard elapsed >= 950_000_000 else { return }
        let seconds = Double(elapsed) / 1_000_000_000
        uploadBytesPerSecond = Double(next.uploadBytes - window.uploadBytes) / seconds
        downloadBytesPerSecond = Double(next.downloadBytes - window.downloadBytes) / seconds
        state = uploadBytesPerSecond > 0 || downloadBytesPerSecond > 0 ? .active : .idle
        self.window = next
    }
}

public func formattedTrafficRate(_ bytesPerSecond: Double) -> String {
    let bytes: Int64
    if !bytesPerSecond.isFinite || bytesPerSecond <= 0 { bytes = 0 }
    else if bytesPerSecond >= Double(Int64.max) { bytes = Int64.max }
    else { bytes = Int64(bytesPerSecond) }
    return ByteCountFormatter.string(fromByteCount: bytes, countStyle: .binary) + "/s"
}
