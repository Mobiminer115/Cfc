import Foundation

struct ByteReader {
    let data: Data

    func u16(at offset: Int) -> UInt16? {
        guard offset >= 0, offset + 2 <= data.count else { return nil }
        return UInt16(data[offset])
            | (UInt16(data[offset + 1]) << 8)
    }

    func u32(at offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= data.count else { return nil }
        return UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
    }

    func i32(at offset: Int) -> Int32? {
        guard let value = u32(at: offset) else { return nil }
        return Int32(bitPattern: value)
    }

    func u64(at offset: Int) -> UInt64? {
        guard offset >= 0, offset + 8 <= data.count else { return nil }
        let low = UInt64(u32(at: offset) ?? 0)
        let high = UInt64(u32(at: offset + 4) ?? 0)
        return low | (high << 32)
    }

    func cString(at offset: Int, limit: Int) -> String {
        guard offset >= 0, offset < data.count else { return "" }
        let end = min(data.count, offset + max(1, limit))
        var bytes: [UInt8] = []
        bytes.reserveCapacity(min(64, end - offset))
        for index in offset..<end {
            let byte = data[index]
            if byte == 0 { break }
            bytes.append(byte)
        }
        return String(bytes: bytes, encoding: .utf8) ??
            String(decoding: bytes, as: UTF8.self)
    }
}

func hexString(_ data: Data, start: Int = 0, count: Int = 16) -> String {
    guard start >= 0, start < data.count else { return "" }
    let end = min(data.count, start + max(0, count))
    return data[start..<end]
        .map { String(format: "%02X", $0) }
        .joined(separator: " ")
}

func hexAddress(_ value: Int) -> String {
    String(format: "0x%lX", UInt64(max(0, value)))
}

func hexAddress(_ value: UInt64) -> String {
    String(format: "0x%llX", value)
}
