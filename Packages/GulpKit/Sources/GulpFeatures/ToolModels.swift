// GulpFeatures — the tool models of one open project. The project window creates one `ToolModels`
// per session and hands each tool view its model, so a tool keeps its state while another tool is
// shown: a running scan, crawl or attack stays under its Pause/Stop controls (and a second one
// cannot start beside it), Repeater drafts and the Decoder input survive, and no subscription is
// started twice. Views never build these models themselves (`View.init` runs on every re-render).

#if canImport(AppKit)
import GulpWorkspace

/// A model that follows the session (event or inbox subscriptions) until told to stop.
@MainActor
protocol SessionFollowing: AnyObject {
    /// End the model's subscriptions and tasks.
    func stop()
}

/// The tool models of one open project, each created on first use and kept until the window closes.
@MainActor
public final class ToolModels {
    let session: ProjectSession
    private var models: [ObjectIdentifier: AnyObject] = [:]

    /// The models for `session`.
    public init(session: ProjectSession) { self.session = session }

    var repeater: RepeaterModel { model(RepeaterModel.init) }
    var fuzzer: FuzzerModel { model(FuzzerModel.init) }
    var activeScan: ActiveScanModel { model(ActiveScanModel.init) }
    var crawler: CrawlerModel { model(CrawlerModel.init) }
    var beacon: BeaconModel { model(BeaconModel.init) }
    var decoder: DecoderModel { model(DecoderModel.init) }
    var comparer: ComparerModel { model(ComparerModel.init) }
    var intercept: InterceptModel { model(InterceptModel.init) }
    var authzMatrix: AuthzMatrixModel { model(AuthzMatrixModel.init) }
    var siteMap: SiteMapModel { model(SiteMapModel.init) }
    var scope: ScopeModel { model(ScopeModel.init) }

    /// Stop every model's subscriptions (the project window is closing).
    public func stop() {
        for case let model as any SessionFollowing in models.values { model.stop() }
    }

    private func model<Model: AnyObject>(_ make: (ProjectSession) -> Model) -> Model {
        let key = ObjectIdentifier(Model.self)
        if let existing = models[key] as? Model { return existing }
        let created = make(session)
        models[key] = created
        return created
    }
}
#endif
