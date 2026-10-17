import XCTest
import CoreGraphics
@testable import RFBProtocol
@testable import RFBRendering

/// Raw/Zlib servers may zero the depth-24 padding byte (wayshare does); the
/// displayed image must stay opaque and keep its colour.
final class FramebufferPaddingTests: XCTestCase {

    func testZeroPaddingByteRendersOpaque() throws {
        let framebuffer = Framebuffer(width: 2, height: 1, pixelFormat: .bgra8888)
        // BGRX little-endian: red, then green, both with a zero fourth byte.
        framebuffer.update(x: 0, y: 0, width: 2, height: 1, data: Data([
            0x00, 0x00, 0xFF, 0x00,
            0x00, 0xFF, 0x00, 0x00,
        ]))

        let image = try XCTUnwrap(framebuffer.createImage())
        var rgba = [UInt8](repeating: 0, count: 8)
        let context = try XCTUnwrap(CGContext(
            data: &rgba, width: 2, height: 1, bitsPerComponent: 8, bytesPerRow: 8,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue))
        context.draw(image, in: CGRect(x: 0, y: 0, width: 2, height: 1))

        XCTAssertEqual(Array(rgba[0..<4]), [0xFF, 0x00, 0x00, 0xFF])
        XCTAssertEqual(Array(rgba[4..<8]), [0x00, 0xFF, 0x00, 0xFF])
    }
}
