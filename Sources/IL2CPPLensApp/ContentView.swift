import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct ContentView: View {
    @State private var isImporterPresented = false
    @State private var isBusy = false
    @State private var report: AnalysisReport?
    @State private var errorMessage: String?
    @State private var searchText = ""

    private var visibleCandidates: [CandidateReport] {
        guard let report else { return [] }
        guard !searchText.isEmpty else { return report.candidates }
        let query = searchText.folding(options: .caseInsensitive, locale: .current)
        return report.candidates.filter { candidate in
            candidate.path.localizedCaseInsensitiveContains(query)
                || candidate.kind.rawValue.localizedCaseInsensitiveContains(query)
                || (candidate.metadata?.symbols.contains { $0.name.localizedCaseInsensitiveContains(query) } ?? false)
        }
    }

    var body: some View {
        NavigationStack {
            Group {
                if isBusy {
                    ProgressView("Đang quét file…")
                        .controlSize(.large)
                } else if let report {
                    resultView(report)
                } else {
                    welcomeView
                }
            }
            .navigationTitle("IL2CPP Lens")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        isImporterPresented = true
                    } label: {
                        Label("Mở file", systemImage: "doc.badge.plus")
                    }
                }
            }
        }
        .sheet(isPresented: $isImporterPresented) {
            UniversalFilePicker { result in
                isImporterPresented = false
                handleImport(result)
            }
            .ignoresSafeArea()
        }
        .alert("Không đọc được file", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Lỗi không xác định")
        }
    }

    private var welcomeView: some View {
        VStack(spacing: 14) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 42))
                .foregroundStyle(.secondary)
            Text("Chưa có file")
                .font(.title2.weight(.semibold))
            Text("Chọn metadata, Mach-O, .ipa, .zip hoặc file bất kỳ. Nếu là thư mục .app, hãy nén ZIP trước. App nhận diện theo chữ ký nội dung, không phụ thuộc tên file.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .padding(.horizontal)
            Button("Chọn file") { isImporterPresented = true }
                .buttonStyle(.borderedProminent)
        }
        .padding()
    }

    @ViewBuilder
    private func resultView(_ report: AnalysisReport) -> some View {
        List {
            Section {
                LabeledContent("Input", value: report.inputName)
                LabeledContent("Candidates", value: "\(report.candidates.count)")
            }

            if !report.warnings.isEmpty {
                Section("Cảnh báo") {
                    ForEach(report.warnings, id: \.self) { warning in
                        Label(warning, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                }
            }

            Section("Kết quả") {
                if report.candidates.isEmpty {
                    Text("Không tìm thấy chữ ký IL2CPP/Mach-O.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(visibleCandidates) { candidate in
                        CandidateRow(candidate: candidate, searchText: searchText)
                    }
                }
            }
        }
        .searchable(text: $searchText, prompt: "Tìm tên type / field / method")
    }

    private func handleImport(_ result: Result<[URL], Error>) {
        switch result {
        case .failure(let error):
            if (error as NSError).code != NSUserCancelledError {
                errorMessage = error.localizedDescription
            }
        case .success(let urls):
            guard let url = urls.first else { return }
            analyze(url: url)
        }
    }

    private func analyze(url: URL) {
        isBusy = true
        report = nil
        errorMessage = nil

        Task {
            do {
                let importedReport = try await Task.detached(priority: .userInitiated) {
                    let didStart = url.startAccessingSecurityScopedResource()
                    defer {
                        if didStart { url.stopAccessingSecurityScopedResource() }
                    }

                    let values = try url.resourceValues(forKeys: [.isRegularFileKey])
                    guard values.isRegularFile == true else {
                        throw ImportError.notARegularFile
                    }
                    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
                    return IL2CPPAnalyzer().analyze(
                        data: data,
                        inputName: url.lastPathComponent
                    )
                }.value
                report = importedReport
            } catch {
                errorMessage = error.localizedDescription
            }
            isBusy = false
        }
    }
}

private enum ImportError: LocalizedError {
    case notARegularFile

    var errorDescription: String? {
        switch self {
        case .notARegularFile:
            return "Hãy chọn file Mach-O, global-metadata.dat hoặc IPA/ZIP. Nếu đang chọn thư mục .app, hãy nén nó thành ZIP trước."
        }
    }
}

/// Copy mode accepts extensionless binaries and gives the app a local,
/// readable URL instead of depending on each file provider's open-in-place behavior.
private struct UniversalFilePicker: UIViewControllerRepresentable {
    let completion: (Result<[URL], Error>) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(completion: completion)
    }

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(
            forOpeningContentTypes: [.item],
            asCopy: true
        )
        picker.delegate = context.coordinator
        picker.allowsMultipleSelection = false
        picker.shouldShowFileExtensions = true
        return picker
    }

    func updateUIViewController(
        _ uiViewController: UIDocumentPickerViewController,
        context: Context
    ) {}

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        private let completion: (Result<[URL], Error>) -> Void

        init(completion: @escaping (Result<[URL], Error>) -> Void) {
            self.completion = completion
        }

        func documentPicker(
            _ controller: UIDocumentPickerViewController,
            didPickDocumentsAt urls: [URL]
        ) {
            completion(.success(urls))
        }

        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
            completion(.failure(CocoaError(.userCancelled)))
        }
    }
}

private struct CandidateRow: View {
    let candidate: CandidateReport
    let searchText: String

    var body: some View {
        DisclosureGroup {
            VStack(alignment: .leading, spacing: 8) {
                LabeledContent("Offset", value: hexAddress(candidate.offset))
                LabeledContent("Bytes", value: "\(candidate.size)")
                LabeledContent("Preview", value: candidate.bytePreview)
                    .font(.system(.caption, design: .monospaced))

                if let metadata = candidate.metadata {
                    MetadataDetails(metadata: metadata, searchText: searchText)
                }
                if let macho = candidate.macho {
                    MachODetails(summary: macho)
                }
            }
            .padding(.vertical, 4)
        } label: {
            HStack {
                Image(systemName: candidate.kind == .metadata ? "list.bullet.rectangle" : "cpu")
                    .foregroundStyle(candidate.kind == .metadata ? .blue : .purple)
                VStack(alignment: .leading) {
                    Text(candidate.kind.rawValue)
                        .font(.headline)
                    Text(candidate.path)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer()
                Text(hexAddress(candidate.offset))
                    .font(.system(.caption, design: .monospaced))
            }
        }
    }
}

private struct MetadataDetails: View {
    let metadata: MetadataReport
    let searchText: String

    private var symbols: [SymbolRow] {
        guard !searchText.isEmpty else { return metadata.symbols }
        return metadata.symbols.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Metadata v\(metadata.version) (profile \(metadata.profile))")
                .font(.headline)
            Text("Header \(hexAddress(metadata.headerSize)) · types \(metadata.typeCount) · fields \(metadata.fieldCount) · methods \(metadata.methodCount) · images \(metadata.imageCount)")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("Tên : metadata+offset : token")
                .font(.caption2)
                .foregroundStyle(.secondary)
            ForEach(symbols) { symbol in
                VStack(alignment: .leading, spacing: 2) {
                    HStack(alignment: .firstTextBaseline) {
                        Text(symbol.name)
                            .font(.system(.body, design: .monospaced))
                            .lineLimit(1)
                        Spacer(minLength: 4)
                        Text(hexAddress(symbol.metadataOffset))
                            .font(.system(.caption, design: .monospaced))
                    }
                    Text("\(symbol.kind) · token \(String(format: "0x%08X", symbol.token)) · \(symbol.detail)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 2)
            }
            if !metadata.warnings.isEmpty {
                ForEach(metadata.warnings, id: \.self) { warning in
                    Text(warning)
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
        }
    }
}

private struct MachODetails: View {
    let summary: MachOSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Mach-O \(summary.format)")
                .font(.headline)
            LabeledContent("CPU", value: summary.cpu)
            LabeledContent("File type", value: String(format: "0x%08X", summary.fileType))
            LabeledContent("Load commands", value: "\(summary.loadCommandCount) (\(summary.commandBytes) bytes)")
            if let imageBase = summary.imageBase {
                LabeledContent("__TEXT base", value: hexAddress(imageBase))
            }
        }
    }
}
