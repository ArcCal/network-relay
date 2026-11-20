import XCTest
@testable import NetworkRelayTunModel

final class RelayEndpointsTests: XCTestCase {
    func testAddressOrderRetainsEveryUsableAnswerOnceAndAlternatesFamilies() {
        let a = "192.0.2.3", b = "192.0.2.4", c = "2001:db8::3", d = "2001:db8::4"
        XCTAssertEqual(RelayEndpoints.candidates([a, b, a, c, d]), [a, c, b, d])
        XCTAssertEqual(RelayEndpoints.candidates([c, d, c, a]), [c, a, d])
        XCTAssertEqual(RelayEndpoints.candidates(["::", "::1", "fe80::1%en0", "ff02::1", "::ffff:127.0.0.1",
            "0.0.0.0", "127.0.0.2", "169.254.1.1", "224.0.0.1", "255.255.255.255", b]), [b])
    }

    func testPinnedIPv6UsesTheSameCertificateNameAndExplicitPort() throws {
        var settings = Settings(serverIP: "2001:0db8::7", domain: "relay.invalid:8443", username: "alice")
        let addresses = try RelayEndpoints.resolve(settings)
        XCTAssertEqual(addresses, ["2001:db8::7"])
        settings.serverIP = try XCTUnwrap(addresses.first)
        let config = try clientConfiguration(settings, password: "fixture")
        XCTAssertTrue(config.contains("https://[2001:db8::7]:8443/"))
        XCTAssertTrue(config.contains("server_name = \"relay.invalid\""))
        settings.serverIP = "fe80::1%en0"
        XCTAssertThrowsError(try RelayEndpoints.resolve(settings))
    }
}
