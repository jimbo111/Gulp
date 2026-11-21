// GulpUI — layout building blocks every tool screen uses: split views whose panes fill the detail
// area, and a wrapping row for filter chips (doc 05 UI-002).

#if canImport(AppKit)
import SwiftUI

/// A horizontal split view whose panes fill its height.
///
/// SwiftUI's `HSplitView` is as tall as its panes' ideal heights, not as tall as the space it is
/// offered: a `List` or `ContentUnavailableView` pane leaves it a band in the middle of the window.
/// `HSplit` gives every pane an infinite maximum height, so the split always fills the detail area.
/// Widths stay the panes' own (`minWidth`/`idealWidth`/`maxWidth`).
public struct HSplit<Content: View>: View {
    private let content: Content

    /// Panes from left to right.
    public init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    /// The split.
    public var body: some View {
        _VariadicView.Tree(Panes(axis: .horizontal)) { content }
    }
}

/// A vertical split view whose panes fill its width; see `HSplit`.
public struct VSplit<Content: View>: View {
    private let content: Content

    /// Panes from top to bottom.
    public init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    /// The split.
    public var body: some View {
        _VariadicView.Tree(Panes(axis: .vertical)) { content }
    }
}

/// Lays the panes out in the AppKit-backed split view, each stretched along the cross axis.
private struct Panes: _VariadicView_MultiViewRoot {
    let axis: Axis

    @ViewBuilder func body(children: _VariadicView.Children) -> some View {
        switch axis {
        case .horizontal:
            HSplitView { ForEach(children) { $0.frame(maxHeight: .infinity) } }
        case .vertical:
            VSplitView { ForEach(children) { $0.frame(maxWidth: .infinity) } }
        }
    }
}

/// A row that wraps onto more lines when its items do not fit (filter chips, doc 05 UI-002).
///
/// Each item keeps its ideal size, so a chip never truncates to "…"; items that do not fit on a line
/// start the next one. Lines are leading-aligned and vertically centered.
public struct FlowLayout: Layout {
    private let spacing: CGFloat
    private let lineSpacing: CGFloat

    /// A wrapping row with `spacing` between items and `lineSpacing` between lines.
    public init(spacing: CGFloat = 8, lineSpacing: CGFloat = 6) {
        self.spacing = spacing
        self.lineSpacing = lineSpacing
    }

    /// The size of the wrapped lines in the proposed width.
    public func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let lines = lines(for: subviews, width: proposal.width ?? .infinity)
        let width = lines.map(\.width).max() ?? 0
        let height = lines.map(\.height).reduce(0, +) + lineSpacing * CGFloat(max(lines.count - 1, 0))
        return CGSize(width: proposal.width.map { min($0, width) } ?? width, height: height)
    }

    /// Places each line's items left to right.
    public func placeSubviews(
        in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()
    ) {
        var y = bounds.minY
        for line in lines(for: subviews, width: bounds.width) {
            var x = bounds.minX
            for (index, size) in zip(line.indices, line.sizes) {
                subviews[index].place(
                    at: CGPoint(x: x, y: y + (line.height - size.height) / 2), anchor: .topLeading,
                    proposal: ProposedViewSize(size))
                x += size.width + spacing
            }
            y += line.height + lineSpacing
        }
    }

    private struct Line {
        var indices: [Int] = []
        var sizes: [CGSize] = []
        var width: CGFloat = 0
        var height: CGFloat = 0
    }

    private func lines(for subviews: Subviews, width: CGFloat) -> [Line] {
        var lines: [Line] = []
        var line = Line()
        for index in subviews.indices {
            var size = subviews[index].sizeThatFits(.unspecified)
            size.width = min(size.width, width)
            let needed = line.indices.isEmpty ? size.width : line.width + spacing + size.width
            if needed > width, !line.indices.isEmpty {
                lines.append(line)
                line = Line()
            }
            line.width = line.indices.isEmpty ? size.width : line.width + spacing + size.width
            line.height = max(line.height, size.height)
            line.indices.append(index)
            line.sizes.append(size)
        }
        if !line.indices.isEmpty { lines.append(line) }
        return lines
    }
}
#endif
