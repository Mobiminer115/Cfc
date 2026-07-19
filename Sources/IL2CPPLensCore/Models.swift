import Foundation

enum CandidateKind: String, Hashable {
    case metadata = "IL2CPP metadata"
    case macho = "Mach-O"
}

struct SymbolRow: Identifiable, Hashable {
    let id: String
    let name: String
    let kind: String
    let metadataOffset: Int
    let token: UInt32
    let detail: String
}

struct MetadataReport: Identifiable, Hashable {
    let id: String
    let version: Int
    let profile: String
    let headerSize: Int
    let stringBytes: Int
    let typeCount: Int
    let fieldCount: Int
    let methodCount: Int
    let imageCount: Int
    let symbols: [SymbolRow]
    let warnings: [String]
}

struct MachOSummary: Hashable {
    let format: String
    let cpu: String
    let fileType: UInt32
    let loadCommandCount: UInt32
    let commandBytes: UInt32
    let imageBase: UInt64?
}

struct CandidateReport: Identifiable, Hashable {
    let id: String
    let path: String
    let kind: CandidateKind
    let offset: Int
    let size: Int
    let bytePreview: String
    let metadata: MetadataReport?
    let macho: MachOSummary?
}

struct AnalysisReport {
    let inputName: String
    let candidates: [CandidateReport]
    let warnings: [String]
}
