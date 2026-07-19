import Foundation
import ZIPFoundation

struct IL2CPPAnalyzer {
    private let maxEntryBytes = 512 * 1024 * 1024
    private let maxArchiveDepth = 2

    func analyze(data: Data, inputName: String) -> AnalysisReport {
        var candidates: [CandidateReport] = []
        var warnings: [String] = []
        scanContainer(
            data: data,
            path: inputName,
            depth: 0,
            candidates: &candidates,
            warnings: &warnings
        )

        var seen = Set<String>()
        candidates = candidates.filter { seen.insert($0.id).inserted }
        if candidates.isEmpty {
            warnings.append("No IL2CPP metadata or Mach-O signature was found. The file may be encrypted, compressed in an unsupported container, or use a newer layout.")
        }
        return AnalysisReport(inputName: inputName, candidates: candidates, warnings: warnings)
    }

    private func scanContainer(
        data: Data,
        path: String,
        depth: Int,
        candidates: inout [CandidateReport],
        warnings: inout [String]
    ) {
        if isZip(data), depth < maxArchiveDepth {
            do {
                guard let archive = try? Archive(data: data, accessMode: .read) else {
                    warnings.append("Could not open archive \(path).")
                    return
                }
                var fileCount = 0
                for entry in archive where entry.type == .file {
                    fileCount += 1
                    var extracted = Data()
                    do {
                        try archive.extract(entry, consumer: { chunk in
                            if extracted.count < maxEntryBytes {
                                let remaining = maxEntryBytes - extracted.count
                                extracted.append(contentsOf: chunk.prefix(remaining))
                            }
                        })
                    } catch {
                        warnings.append("Could not read \(path)!\(entry.path): \(error.localizedDescription)")
                        continue
                    }
                    if extracted.count >= maxEntryBytes {
                        warnings.append("Skipped bytes after the \(maxEntryBytes / (1024 * 1024)) MB limit for \(path)!\(entry.path).")
                    }
                    scanContainer(
                        data: extracted,
                        path: "\(path)!\(entry.path)",
                        depth: depth + 1,
                        candidates: &candidates,
                        warnings: &warnings
                    )
                }
                if fileCount == 0 {
                    warnings.append("Archive \(path) contains no regular files.")
                }
            } catch {
                warnings.append("Archive scan failed for \(path): \(error.localizedDescription)")
            }
            return
        }

        scanRaw(data: data, path: path, candidates: &candidates)
    }

    private func scanRaw(data: Data, path: String, candidates: inout [CandidateReport]) {
        guard data.count >= 4 else { return }
        let reader = ByteReader(data: data)

        if data.count >= 4 {
            for offset in 0...(data.count - 4) {
                if reader.u32(at: offset) == 0xFAB11BAF,
                   let metadata = MetadataParser(data: data, baseOffset: offset).parse() {
                    candidates.append(CandidateReport(
                        id: "\(path)|metadata|\(offset)",
                        path: path,
                        kind: .metadata,
                        offset: offset,
                        size: data.count - offset,
                        bytePreview: hexString(data, start: offset),
                        metadata: metadata,
                        macho: nil
                    ))
                }
            }
        }

        // Mach-O headers are aligned in normal files. Scanning on four-byte
        // boundaries avoids most random false positives in large data blobs.
        if data.count >= 4 {
            for offset in stride(from: 0, through: data.count - 4, by: 4) {
                guard let summary = machoSummary(data: data, offset: offset) else { continue }
                candidates.append(CandidateReport(
                    id: "\(path)|macho|\(offset)",
                    path: path,
                    kind: .macho,
                    offset: offset,
                    size: data.count - offset,
                    bytePreview: hexString(data, start: offset),
                    metadata: nil,
                    macho: summary
                ))
            }
        }
    }

    private func isZip(_ data: Data) -> Bool {
        guard data.count >= 4 else { return false }
        let signature = Array(data.prefix(4))
        return signature == [0x50, 0x4B, 0x03, 0x04]
            || signature == [0x50, 0x4B, 0x05, 0x06]
            || signature == [0x50, 0x4B, 0x07, 0x08]
    }

    private func machoSummary(data: Data, offset: Int) -> MachOSummary? {
        let reader = ByteReader(data: data)
        guard let magic = reader.u32(at: offset) else { return nil }

        switch magic {
        case 0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE:
            let is64 = magic == 0xFEEDFACF || magic == 0xCFFAEDFE
            let littleEndian = magic == 0xFEEDFACE || magic == 0xFEEDFACF
            guard let cpu = endianU32(data: data, offset: offset + 4, little: littleEndian),
                  let fileType = endianU32(data: data, offset: offset + 12, little: littleEndian),
                  let commandCount = endianU32(data: data, offset: offset + 16, little: littleEndian),
                  let commandBytes = endianU32(data: data, offset: offset + 20, little: littleEndian) else {
                return nil
            }
            let headerSize = is64 ? 32 : 28
            let commandEnd = UInt64(offset) + UInt64(headerSize) + UInt64(commandBytes)
            guard commandEnd <= UInt64(data.count) else { return nil }
            let cpuName = cpuName(cpu)
            return MachOSummary(
                format: is64 ? "thin 64-bit" : "thin 32-bit",
                cpu: cpuName,
                fileType: fileType,
                loadCommandCount: commandCount,
                commandBytes: commandBytes,
                imageBase: findImageBase(data: data, offset: offset, is64: is64, littleEndian: littleEndian, commandCount: commandCount, commandBytes: commandBytes)
            )
        case 0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA:
            let littleEndian = magic == 0xCAFEBABE || magic == 0xCAFEBABF
            guard let count = endianU32(data: data, offset: offset + 4, little: littleEndian), count > 0, count < 128 else { return nil }
            let is64Table = magic == 0xCAFEBABF || magic == 0xBFBAFECA
            let entrySize = is64Table ? 32 : 20
            let end = UInt64(offset) + 8 + UInt64(count) * UInt64(entrySize)
            guard end <= UInt64(data.count) else { return nil }
            return MachOSummary(
                format: is64Table ? "fat 64-bit table" : "fat/universal",
                cpu: "multiple architectures",
                fileType: 0,
                loadCommandCount: count,
                commandBytes: UInt32(entrySize),
                imageBase: nil
            )
        default:
            return nil
        }
    }

    private func findImageBase(
        data: Data,
        offset: Int,
        is64: Bool,
        littleEndian: Bool,
        commandCount: UInt32,
        commandBytes: UInt32
    ) -> UInt64? {
        let headerSize = is64 ? 32 : 28
        var cursor = offset + headerSize
        let end = cursor + Int(commandBytes)
        let segmentCommand: UInt32 = is64 ? 0x19 : 0x1
        for _ in 0..<commandCount {
            guard cursor + 8 <= end,
                  let command = endianU32(data: data, offset: cursor, little: littleEndian),
                  let size = endianU32(data: data, offset: cursor + 4, little: littleEndian),
                  size >= 8,
                  cursor + Int(size) <= end else { break }
            if command == segmentCommand {
                let nameOffset = cursor + 8
                let nameBytes = data[nameOffset..<min(nameOffset + 16, data.count)]
                let name = String(bytes: nameBytes.prefix { $0 != 0 }, encoding: .utf8) ?? ""
                if name == "__TEXT" {
                    let vmOffset = is64 ? cursor + 24 : cursor + 24
                    return is64
                        ? endianU64(data: data, offset: vmOffset, little: littleEndian)
                        : UInt64(endianU32(data: data, offset: vmOffset, little: littleEndian) ?? 0)
                }
            }
            cursor += Int(size)
        }
        return nil
    }

    private func endianU32(data: Data, offset: Int, little: Bool) -> UInt32? {
        guard offset >= 0, offset + 4 <= data.count else { return nil }
        let bytes = data[offset..<(offset + 4)]
        if little {
            return bytes.enumerated().reduce(UInt32(0)) { result, item in
                result | (UInt32(item.element) << UInt32(item.offset * 8))
            }
        }
        return bytes.enumerated().reduce(UInt32(0)) { result, item in
            result | (UInt32(item.element) << UInt32((3 - item.offset) * 8))
        }
    }

    private func endianU64(data: Data, offset: Int, little: Bool) -> UInt64? {
        guard offset >= 0, offset + 8 <= data.count else { return nil }
        let bytes = data[offset..<(offset + 8)]
        if little {
            return bytes.enumerated().reduce(UInt64(0)) { result, item in
                result | (UInt64(item.element) << UInt64(item.offset * 8))
            }
        }
        return bytes.enumerated().reduce(UInt64(0)) { result, item in
            result | (UInt64(item.element) << UInt64((7 - item.offset) * 8))
        }
    }

    private func cpuName(_ cpu: UInt32) -> String {
        switch cpu {
        case 0x0100000C: return "arm64"
        case 12: return "arm"
        case 0x01000007: return "x86_64"
        case 7: return "x86"
        default: return String(format: "cpu 0x%08X", cpu)
        }
    }
}
