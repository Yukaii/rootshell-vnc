import XCTest
import RFBProtocol
@testable import rootshellVNC

final class RemoteSystemTests: XCTestCase {

    func testAutomaticTreatsMacSecurityListAsMac() {
        XCTAssertTrue(VNCConfiguration.RemoteSystem.automatic.usesAppleModifiers(
            isAppleProtocol: true,
            offeredSecurityTypes: [.apple30, .macAuthentication, .appleSRP]))
    }

    func testAutomaticTreatsSRPOnlyAppleServerAsLinux() {
        XCTAssertFalse(VNCConfiguration.RemoteSystem.automatic.usesAppleModifiers(
            isAppleProtocol: true,
            offeredSecurityTypes: [.appleSRP]))
    }

    func testAutomaticKeepsStandardConventionForRegularServers() {
        XCTAssertFalse(VNCConfiguration.RemoteSystem.automatic.usesAppleModifiers(
            isAppleProtocol: false,
            offeredSecurityTypes: [.vncAuthentication]))
    }

    func testExplicitChoicesOverrideTheHandshake() {
        XCTAssertTrue(VNCConfiguration.RemoteSystem.mac.usesAppleModifiers(
            isAppleProtocol: true,
            offeredSecurityTypes: [.appleSRP]))
        XCTAssertFalse(VNCConfiguration.RemoteSystem.other.usesAppleModifiers(
            isAppleProtocol: true,
            offeredSecurityTypes: [.apple30, .macAuthentication]))
    }
}
