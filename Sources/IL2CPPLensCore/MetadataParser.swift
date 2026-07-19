import Foundation

private let metadataMagic: UInt32 = 0xFAB11BAF

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

    init(data: Data, baseOffset: Int = 0) {
        self.data = data
        self.baseOffset = baseOffset
        self.reader = ByteReader(data: data)
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
        var warnings: [String] = []

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
            let tokenOffset = version >= 31 ? offset + 28 : offset + 24
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
