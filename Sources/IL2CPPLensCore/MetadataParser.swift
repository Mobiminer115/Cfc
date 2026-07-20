import Foundation

private let metadataMagic: UInt32 = 0xFAB11BAF
// This build uses a small custom loader which checks this magic before
// decoding the first 0x100 bytes of global-metadata.dat. The payload tables
// remain ordinary IL2CPP tables after the header is decoded.
private let protectedMetadataMagic: UInt32 = 0xEAB11BAF

private struct HeaderField {
    let name: String
    let minimum: Double
    let maximum: Double

    init(_ name: String, minimum: Double = 0, maximum: Double = 10_000) {
        self.name = name
        self.minimum = minimum
        self.maximum = maximum
    }

    func enabled(for version: Double) -> Bool {
        minimum <= version && version <= maximum
    }
}

private struct TableRange {
    let offset: Int
    let size: Int

    var end: Int { offset + size }
}

private struct TypeRecord {
    let index: Int
    let name: String
    let namespace: String
    let fieldStart: Int
    let fieldCount: Int
    let methodStart: Int
    let methodCount: Int
    let token: UInt32

    var fullName: String {
        namespace.isEmpty ? name : "\(namespace).\(name)"
    }
}

private struct FieldRecord {
    let index: Int
    let name: String
    let typeIndex: Int
    let token: UInt32
    let metadataOffset: Int
}

private struct MethodRecord {
    let index: Int
    let name: String
    let declaringType: Int
    let token: UInt32
    let metadataOffset: Int
}

struct MetadataParser {
    private let data: Data
    private let baseOffset: Int
    private let reader: ByteReader
    private let protectedHeaderDetected: Bool

    init(data: Data, baseOffset: Int = 0) {
        let originalReader = ByteReader(data: data)
        let isProtected = originalReader.u32(at: baseOffset) == protectedMetadataMagic
        let normalizedData = isProtected
            ? Self.decodeProtectedHeader(data: data, baseOffset: baseOffset) ?? data
            : data
        self.data = normalizedData
        self.baseOffset = baseOffset
        self.reader = ByteReader(data: normalizedData)
        self.protectedHeaderDetected = isProtected
    }

    func parse() -> MetadataReport? {
        guard reader.u32(at: baseOffset) == metadataMagic,
              let rawVersion = reader.i32(at: baseOffset + 4),
              rawVersion >= 19,
              rawVersion <= 40 else {
            return nil
        }

        let version = Int(rawVersion)
        let profile = rawVersion == 24 ? 24.5 : Double(rawVersion)
        let fields = Self.headerFields.filter { $0.enabled(for: profile) }
        var tables: [String: TableRange] = [:]
        var cursor = baseOffset + 8
        var warnings: [String] = protectedHeaderDetected
            ? ["Decoded custom IL2CPP metadata header (original magic 0xEAB11BAF)."]
            : []

        for field in fields {
            guard let relativeOffset = reader.u32(at: cursor),
                  let rawSize = reader.u32(at: cursor + 4) else {
                return nil
            }
            cursor += 8
            let relative = Int(relativeOffset)
            let size = Int(rawSize)
            guard relative >= 0, size >= 0,
                  relative <= data.count - baseOffset,
                  size <= data.count - baseOffset - relative else {
                return nil
            }
            tables[field.name] = TableRange(
                offset: baseOffset + relative,
                size: size
            )
        }

        guard cursor <= data.count else { return nil }
        let essential = ["strings", "type_definitions", "fields", "methods"]
        let plausible = essential.compactMap { tables[$0] }
            .filter { $0.offset >= cursor || $0.size == 0 }
        guard plausible.count >= 3 else { return nil }

        let stringTable = tables["strings"]
        let strings = StringTable(data: data, table: stringTable)
        let types = readTypes(tables["type_definitions"], version: profile, strings: strings)
        let fieldsRecords = readFields(tables["fields"], version: profile, strings: strings)
        let methods = readMethods(tables["methods"], version: profile, strings: strings)
        let imageCount = recordCount(tables["images"], recordSize: imageRecordSize(version: profile))

        if version < 27 || version > 31 {
            warnings.append("Parser reads the common v27–v31 record layouts; this file reports v\(version). Header and names may still be useful, but verify offsets before patching.")
        }

        let maxSymbols = 8_000
        var symbols: [SymbolRow] = []
        symbols.reserveCapacity(min(maxSymbols, fieldsRecords.count + methods.count + types.count))

        for type in types {
            guard symbols.count < maxSymbols else { break }
            symbols.append(SymbolRow(
                id: "type-\(type.index)-\(type.name)",
                name: type.fullName,
                kind: "type",
                metadataOffset: tableOffset(tables["type_definitions"], index: type.index, recordSize: typeRecordSize(version: profile)),
                token: type.token,
                detail: "fields \(type.fieldStart) + \(type.fieldCount), methods \(type.methodStart) + \(type.methodCount)"
            ))

            let fieldEnd = type.fieldStart + type.fieldCount
            if type.fieldStart >= 0, fieldEnd >= type.fieldStart,
               fieldEnd <= fieldsRecords.count {
                for field in fieldsRecords[type.fieldStart..<fieldEnd] {
                    guard symbols.count < maxSymbols else { break }
                    symbols.append(SymbolRow(
                        id: "field-\(field.index)-\(type.fullName).\(field.name)",
                        name: "\(type.fullName).\(field.name)",
                        kind: "field",
                        metadataOffset: field.metadataOffset,
                        token: field.token,
                        detail: "type index \(field.typeIndex)"
                    ))
                }
            }

            let methodEnd = type.methodStart + type.methodCount
            if type.methodStart >= 0, methodEnd >= type.methodStart,
               methodEnd <= methods.count {
                for method in methods[type.methodStart..<methodEnd] {
                    guard symbols.count < maxSymbols else { break }
                    symbols.append(SymbolRow(
                        id: "method-\(method.index)-\(type.fullName).\(method.name)",
                        name: "\(type.fullName).\(method.name)",
                        kind: "method",
                        metadataOffset: method.metadataOffset,
                        token: method.token,
                        detail: "declaring type index \(method.declaringType)"
                    ))
                }
            }
        }

        if symbols.count == maxSymbols {
            warnings.append("Symbol list capped at \(maxSymbols) rows. Counts above are still the full table counts.")
        }

        return MetadataReport(
            id: "metadata-\(baseOffset)-\(version)",
            version: version,
            profile: String(format: "%g", profile),
            headerSize: cursor - baseOffset,
            stringBytes: stringTable?.size ?? 0,
            typeCount: recordCount(tables["type_definitions"], recordSize: typeRecordSize(version: profile)),
            fieldCount: recordCount(tables["fields"], recordSize: fieldRecordSize(version: profile)),
            methodCount: recordCount(tables["methods"], recordSize: methodRecordSize(version: profile)),
            imageCount: imageCount,
            symbols: symbols,
            warnings: warnings
        )
    }

    // The supplied UnityFramework contains the metadata loader for this
    // protection. It checks 0xEAB11BAF, then decodes the first 0xC8 bytes with
    // a fixed 32-bit key and writes the result into a normal v29 header. The
    // table payloads are not encrypted, so only this small header needs to be
    // transformed before the regular parser runs.
    private static func decodeProtectedHeader(data: Data, baseOffset: Int) -> Data? {
        guard baseOffset >= 0, baseOffset + 0x100 <= data.count else { return nil }

        // keyKind: 0 = XOR with key, 1 = XOR with (key + value),
        // 2 = XOR with (key | value).
        let operations: [(source: Int, destination: Int, subtract: UInt32, keyKind: UInt8, keyValue: UInt32)] = [
            (0x08, 0x10, 0x00, 0, 0x00),
            (0x0C, 0x14, 0x00, 0, 0x00),
            (0x10, 0x20, 0x03, 1, 0x01),
            (0x14, 0x24, 0x07, 2, 0x02),
            (0x18, 0x30, 0x06, 2, 0x02),
            (0x1C, 0x34, 0x0E, 1, 0x04),
            (0x20, 0x40, 0x09, 1, 0x03),
            (0x24, 0x44, 0x15, 1, 0x06),
            (0x28, 0x50, 0x0C, 1, 0x04),
            (0x2C, 0x54, 0x1C, 1, 0x08),
            (0x30, 0x18, 0x0F, 1, 0x05),
            (0x34, 0x1C, 0x23, 1, 0x0A),
            (0x38, 0x28, 0x12, 1, 0x06),
            (0x3C, 0x2C, 0x2A, 1, 0x0C),
            (0x40, 0x38, 0x15, 1, 0x07),
            (0x44, 0x3C, 0x31, 1, 0x0E),
            (0x48, 0x48, 0x18, 1, 0x08),
            (0x4C, 0x4C, 0x38, 2, 0x10),
            (0x50, 0x58, 0x1B, 1, 0x09),
            (0x54, 0x5C, 0x3F, 2, 0x12),
            (0x58, 0x08, 0x1E, 1, 0x0A),
            (0x5C, 0x0C, 0x46, 1, 0x14),
            (0x60, 0xC0, 0x21, 1, 0x0B),
            (0x64, 0xC4, 0x4D, 1, 0x16),
            (0x68, 0xB8, 0x24, 1, 0x0C),
            (0x6C, 0xBC, 0x54, 1, 0x18),
            (0x70, 0xB0, 0x27, 1, 0x0D),
            (0x74, 0xB4, 0x5B, 1, 0x1A),
            (0x78, 0xA8, 0x2A, 1, 0x0E),
            (0x7C, 0xAC, 0x62, 1, 0x1C),
            (0x80, 0x60, 0x2D, 1, 0x0F),
            (0x84, 0x64, 0x69, 1, 0x1E),
            (0x88, 0x70, 0x30, 2, 0x10),
            (0x8C, 0x74, 0x70, 1, 0x20),
            (0x90, 0x80, 0x33, 1, 0x11),
            (0x94, 0x84, 0x77, 1, 0x22),
            (0x98, 0x90, 0x36, 2, 0x12),
            (0x9C, 0x94, 0x7E, 1, 0x24),
            (0xA0, 0xA0, 0x39, 1, 0x13),
            (0xA4, 0xA4, 0x85, 1, 0x26),
            (0xA8, 0x68, 0x3C, 1, 0x14),
            (0xAC, 0x6C, 0x8C, 1, 0x28),
            (0xB0, 0x78, 0x3F, 1, 0x15),
            (0xB4, 0x7C, 0x93, 1, 0x2A),
            (0xB8, 0x88, 0x42, 1, 0x16),
            (0xBC, 0x8C, 0x9A, 1, 0x2C),
            (0xC0, 0x98, 0x45, 1, 0x17),
            (0xC4, 0x9C, 0xA1, 1, 0x2E)
        ]

        let sourceReader = ByteReader(data: data)
        var decoded = data
        let key: UInt32 = 0x00A8C72D

        for operation in operations {
            guard let source = sourceReader.u32(at: baseOffset + operation.source) else {
                return nil
            }

            let mask: UInt32
            switch operation.keyKind {
            case 0:
                mask = key
            case 1:
                mask = key &+ operation.keyValue
            default:
                mask = key | operation.keyValue
            }
            let value = (source &- operation.subtract) ^ mask
            writeU32(value, to: &decoded, at: baseOffset + operation.destination)
        }

        // The loader preserves the version and all words from 0xC8 onward;
        // normalize only the magic so the ordinary header parser accepts it.
        writeU32(metadataMagic, to: &decoded, at: baseOffset)
        return decoded
    }

    private static func writeU32(_ value: UInt32, to data: inout Data, at offset: Int) {
        guard offset >= 0, offset + 4 <= data.count else { return }
        data.replaceSubrange(
            offset..<(offset + 4),
            with: [
                UInt8(truncatingIfNeeded: value),
                UInt8(truncatingIfNeeded: value >> 8),
                UInt8(truncatingIfNeeded: value >> 16),
                UInt8(truncatingIfNeeded: value >> 24)
            ]
        )
    }

    private func readTypes(_ table: TableRange?, version: Double, strings: StringTable) -> [TypeRecord] {
        guard let table else { return [] }
        let recordSize = typeRecordSize(version: version)
        let count = recordCount(table, recordSize: recordSize)
        var result: [TypeRecord] = []
        result.reserveCapacity(min(count, 2_000_000))
        for index in 0..<count {
            let offset = table.offset + index * recordSize
            guard let nameIndex = reader.i32(at: offset),
                  let namespaceIndex = reader.i32(at: offset + 4),
                  let fieldStart = reader.i32(at: offset + 32),
                  let methodStart = reader.i32(at: offset + 36),
                  let methodCount = reader.u16(at: offset + 64),
                  let fieldCount = reader.u16(at: offset + 68) else {
                break
            }
            let token = reader.u32(at: offset + 84) ?? 0
            result.append(TypeRecord(
                index: index,
                name: strings.value(at: Int(nameIndex)),
                namespace: strings.value(at: Int(namespaceIndex)),
                fieldStart: Int(fieldStart),
                fieldCount: Int(fieldCount),
                methodStart: Int(methodStart),
                methodCount: Int(methodCount),
                token: token
            ))
        }
        return result
    }

    private func readFields(_ table: TableRange?, version: Double, strings: StringTable) -> [FieldRecord] {
        guard let table else { return [] }
        let recordSize = fieldRecordSize(version: version)
        let count = recordCount(table, recordSize: recordSize)
        var result: [FieldRecord] = []
        result.reserveCapacity(min(count, 2_000_000))
        for index in 0..<count {
            let offset = table.offset + index * recordSize
            guard let nameIndex = reader.u32(at: offset),
                  let typeIndex = reader.i32(at: offset + 4) else { break }
            result.append(FieldRecord(
                index: index,
                name: strings.value(at: Int(nameIndex)),
                typeIndex: Int(typeIndex),
                token: reader.u32(at: offset + 8) ?? 0,
                metadataOffset: offset - baseOffset
            ))
        }
        return result
    }

    private func readMethods(_ table: TableRange?, version: Double, strings: StringTable) -> [MethodRecord] {
        guard let table else { return [] }
        let recordSize = methodRecordSize(version: version)
        let count = recordCount(table, recordSize: recordSize)
        var result: [MethodRecord] = []
        result.reserveCapacity(min(count, 2_000_000))
        for index in 0..<count {
            let offset = table.offset + index * recordSize
            guard let nameIndex = reader.u32(at: offset),
                  let declaringType = reader.i32(at: offset + 4) else { break }
            // v25–v30 store the token at +20. v31 adds a return-parameter
            // token and moves it to +24.
            let tokenOffset = version >= 31 ? offset + 24 : (version >= 25 ? offset + 20 : offset + 24)
            result.append(MethodRecord(
                index: index,
                name: strings.value(at: Int(nameIndex)),
                declaringType: Int(declaringType),
                token: reader.u32(at: tokenOffset) ?? 0,
                metadataOffset: offset - baseOffset
            ))
        }
        return result
    }

    private func recordCount(_ table: TableRange?, recordSize: Int) -> Int {
        guard let table, recordSize > 0 else { return 0 }
        return min(table.size / recordSize, 2_000_000)
    }

    private func tableOffset(_ table: TableRange?, index: Int, recordSize: Int) -> Int {
        guard let table else { return index * recordSize }
        return table.offset - baseOffset + index * recordSize
    }

    private static let headerFields: [HeaderField] = [
        HeaderField("string_literals"),
        HeaderField("string_literal_data"),
        HeaderField("strings"),
        HeaderField("events"),
        HeaderField("properties"),
        HeaderField("methods"),
        HeaderField("parameter_default_values"),
        HeaderField("field_default_values"),
        HeaderField("field_and_parameter_default_value_data"),
        HeaderField("field_marshaled_sizes"),
        HeaderField("parameters"),
        HeaderField("fields"),
        HeaderField("generic_parameters"),
        HeaderField("generic_parameter_constraints"),
        HeaderField("generic_containers"),
        HeaderField("nested_types"),
        HeaderField("interfaces"),
        HeaderField("vtable_methods"),
        HeaderField("interface_offsets"),
        HeaderField("type_definitions"),
        HeaderField("rgctx_entries", maximum: 24.1),
        HeaderField("images"),
        HeaderField("assemblies"),
        HeaderField("metadata_usage_lists", minimum: 19, maximum: 24.5),
        HeaderField("metadata_usage_pairs", minimum: 19, maximum: 24.5),
        HeaderField("field_refs", minimum: 19),
        HeaderField("referenced_assemblies", minimum: 20),
        HeaderField("attributes_info", minimum: 21, maximum: 27.2),
        HeaderField("attribute_types", minimum: 21, maximum: 27.2),
        HeaderField("attribute_data", minimum: 29),
        HeaderField("attribute_data_ranges", minimum: 29),
        HeaderField("unresolved_virtual_call_parameter_types", minimum: 22),
        HeaderField("unresolved_virtual_call_parameter_ranges", minimum: 22),
        HeaderField("windows_runtime_type_names", minimum: 23),
        HeaderField("windows_runtime_strings", minimum: 27),
        HeaderField("exported_type_definitions", minimum: 24)
    ]
}

private struct StringTable {
    let data: Data
    let table: TableRange?
    let reader: ByteReader

    init(data: Data, table: TableRange?) {
        self.data = data
        self.table = table
        self.reader = ByteReader(data: data)
    }

    func value(at index: Int) -> String {
        guard let table, index >= 0, index < table.size else {
            return "<string#\(index)>"
        }
        return reader.cString(at: table.offset + index, limit: table.end - (table.offset + index))
    }
}

private func typeRecordSize(version: Double) -> Int {
    // v25+ Il2CppTypeDefinition is 88 bytes.
    version >= 25 ? 88 : 92
}

private func fieldRecordSize(version: Double) -> Int {
    version >= 25 ? 12 : 16
}

private func methodRecordSize(version: Double) -> Int {
    version >= 31 ? 36 : (version >= 25 ? 32 : 48)
}

private func imageRecordSize(version: Double) -> Int {
    version >= 24.1 ? 40 : 24
}
