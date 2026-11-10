// GulpFeatures — Proxy → Match & Replace (F01 PRX-020…PRX-022): the ordered rule list with the
// built-in presets, edited in place and applied to the project.

#if canImport(AppKit)
import GulpProxy
import GulpWorkspace
import SwiftUI

/// Proxy → Match & Replace.
public struct MatchReplaceView: View {
    let session: ProjectSession
    @State private var rules: [MatchReplaceRule]
    @State private var selection: MatchReplaceRule.ID?
    @State private var status: String?

    /// The rule editor for `session`.
    public init(session: ProjectSession) {
        self.session = session
        _rules = State(initialValue: session.settings.get(MatchReplaceSettings.self).rules)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Button("Add") {
                    let rule = MatchReplaceRule(kind: .requestHeader, match: "", replace: "")
                    rules.append(rule)
                    selection = rule.id
                }
                Button("Remove") { rules.removeAll { $0.id == selection } }.disabled(selection == nil)
                Button("Up") { move(-1) }.disabled(selection == nil)
                Button("Down") { move(1) }.disabled(selection == nil)
                Button("Restore presets") {
                    let missing = MatchReplaceRule.presets.filter { preset in
                        !rules.contains { $0.comment == preset.comment && $0.match == preset.match }
                    }
                    rules += missing
                }
                Spacer()
                if let status { Text(status).foregroundStyle(.secondary) }
                Button("Apply") { apply() }.keyboardShortcut(.defaultAction)
            }
            .controlSize(.small)
            .padding(6)
            Divider()
            List(selection: $selection) {
                ForEach($rules) { $rule in
                    HStack(spacing: 8) {
                        Toggle("", isOn: $rule.enabled).labelsHidden()
                        Picker("", selection: $rule.kind) {
                            ForEach(MatchReplaceKind.allCases, id: \.self) { Text(Self.label($0)) }
                        }
                        .labelsHidden()
                        .frame(width: 170)
                        TextField("Match (empty adds a header)", text: $rule.match)
                            .font(.system(.body, design: .monospaced))
                        TextField("Replace", text: $rule.replace)
                            .font(.system(.body, design: .monospaced))
                        Toggle("Regex", isOn: $rule.isRegex)
                        Toggle("Tools", isOn: $rule.applyToTools)
                            .help("Also apply to Repeater, Fuzzer, Scanner… (PRX-021)")
                        TextField("When (GulpQL)", text: $rule.when)
                            .font(.system(.body, design: .monospaced))
                            .frame(width: 200)
                            .help(
                                #"PRX-025: apply only when this GulpQL condition holds, e.g. req.host ~ "api""#
                            )
                        TextField("Comment", text: $rule.comment).frame(width: 160)
                    }
                    .tag(rule.id)
                }
            }
        }
        .navigationTitle("Match & Replace")
    }

    private func move(_ offset: Int) {
        guard let index = rules.firstIndex(where: { $0.id == selection }) else { return }
        let target = index + offset
        guard rules.indices.contains(target) else { return }
        rules.swapAt(index, target)
    }

    private func apply() {
        let session = self.session
        let rules = self.rules
        Task {
            do {
                try await session.setMatchReplaceRules(rules)
                status = "Applied \(rules.filter(\.enabled).count) active rule(s)"
            } catch {
                status = "Not saved: \(error)"
            }
        }
    }

    static func label(_ kind: MatchReplaceKind) -> String {
        switch kind {
        case .requestHeader: "Request header"
        case .requestBody: "Request body"
        case .requestFirstLine: "Request first line"
        case .requestParamName: "Request param name"
        case .requestParamValue: "Request param value"
        case .responseHeader: "Response header"
        case .responseBody: "Response body"
        case .responseFirstLine: "Response first line"
        case .webSocketToServer: "WS to server"
        case .webSocketToClient: "WS to client"
        }
    }
}

/// The Proxy tool: HTTP History, Intercept, Match & Replace and WebSockets History tabs.
public struct ProxyToolView: View {
    let session: ProjectSession
    let generation: Int
    @AppStorage("gulp.proxy.tab") private var tab = 0

    /// The Proxy tool for `session`; bump `generation` after the project file changes.
    public init(session: ProjectSession, generation: Int) {
        self.session = session
        self.generation = generation
    }

    public var body: some View {
        TabView(selection: $tab) {
            SessionHistoryView(session: session, generation: generation)
                .tabItem { Text("HTTP History") }
                .tag(0)
            InterceptView(session: session)
                .tabItem { Text("Intercept") }
                .tag(1)
            MatchReplaceView(session: session)
                .tabItem { Text("Match & Replace") }
                .tag(2)
            SessionWebSocketHistoryView(session: session, generation: generation)
                .tabItem { Text("WebSockets History") }
                .tag(3)
        }
    }
}
#endif
