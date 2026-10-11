import AppKit
import SwiftUI

/// Presentation only. These colors follow the system's light/dark appearance.
enum NFStyle {
    static let accent = Color(red: 0.12, green: 0.48, blue: 0.86)
    static let aqua = Color(red: 0.10, green: 0.67, blue: 0.73)
    static let background = Color(nsColor: .windowBackgroundColor)
    static let surface = Color(nsColor: .controlBackgroundColor)
    static let outline = Color.primary.opacity(0.08)
}

private struct NFCard: ViewModifier {
    @Environment(\.colorSchemeContrast) private var contrast

    func body(content: Content) -> some View {
        content
            .background {
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(NFStyle.surface.opacity(contrast == .increased ? 1 : 0.8))
            }
            .overlay {
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .strokeBorder(Color.primary.opacity(contrast == .increased ? 0.3 : 0.08))
                    .allowsHitTesting(false)
            }
    }
}

extension View {
    func nfCard() -> some View { modifier(NFCard()) }
}

struct NFBrandMark: View {
    var size: CGFloat = 36

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
                .fill(LinearGradient(colors: [NFStyle.accent, NFStyle.aqua],
                                     startPoint: .topLeading, endPoint: .bottomTrailing))
            Text("N")
                .font(.system(size: size * 0.55, weight: .semibold, design: .rounded))
                .foregroundStyle(.white)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
