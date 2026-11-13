// gulp-vulnlab — a tiny GraphQL endpoint (F23 §5, the M13b GraphQL DoD). It is not a real GraphQL
// engine: it pattern-matches the two queries the lab needs and serves a canned introspection schema.
//
//   POST /graphql        introspection → the schema; `{ user(id: N) { … email … } }` → the user with
//                        their email for ANY id and no auth (broken object/field authorization);
//                        `{ me { … } }` → requires the session cookie.
//   POST /safe/graphql   introspection is disabled; `user` returns only the caller's own record and
//                        never another user's email.

import Foundation
import GulpCore

enum GraphQLLab {
    static let users: [Int: (name: String, email: String)] = [
        1: ("alice", "alice@vulnlab.test"), 2: ("bob", "bob@secret.test"),
    ]

    static func json(_ status: Int, _ body: String) -> VulnReply {
        VulnReply(bytes: VulnLab.response(status, body: Array(body.utf8), type: "application/json"))
    }

    static func respond(_ request: RawRequest, path: String) -> VulnReply? {
        guard path == "/graphql" || path == "/safe/graphql" else { return nil }
        let safe = path.hasPrefix("/safe/")
        guard request.bytes[request.parsed.method].string().uppercased() == "POST" else {
            return json(405, #"{"errors":[{"message":"use POST"}]}"#)
        }
        let body = Data(request.bytes.rawBytes[request.parsed.body])
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
            let query = root["query"] as? String
        else { return json(400, #"{"errors":[{"message":"no query"}]}"#) }

        if query.contains("__schema") || query.contains("IntrospectionQuery") {
            if safe { return json(400, #"{"errors":[{"message":"GraphQL introspection is disabled"}]}"#) }
            return json(200, introspectionJSON)
        }
        if query.contains("user") {
            // Parse `user(id: N)`.
            let id =
                query.range(of: #"user\s*\(\s*id\s*:\s*(\d+)"#, options: .regularExpression)
                .flatMap { Int(query[$0].filter(\.isNumber)) } ?? 1
            guard let user = users[id] else { return json(200, #"{"data":{"user":null}}"#) }
            let wantsEmail = query.contains("email")
            if safe {
                // The enforcing twin: a session is required and only your own record (no email leak).
                guard let session = AuthLab.cookie(request, "session"),
                    let who = AuthLab.sessionUser(session),
                    who == user.name
                else { return json(200, #"{"data":{"user":null},"errors":[{"message":"forbidden"}]}"#) }
                return json(200, #"{"data":{"user":{"id":\#(id),"name":"\#(user.name)"}}}"#)
            }
            // The vulnerable endpoint: anyone gets any user, email included (broken field authz).
            let emailField = wantsEmail ? #","email":"\#(user.email)""# : ""
            return json(200, #"{"data":{"user":{"id":\#(id),"name":"\#(user.name)"\#(emailField)}}}"#)
        }
        if query.contains("me") {
            guard let session = AuthLab.cookie(request, "session"), let who = AuthLab.sessionUser(session)
            else {
                return json(200, #"{"data":{"me":null},"errors":[{"message":"not authenticated"}]}"#)
            }
            return json(200, #"{"data":{"me":{"name":"\#(who)"}}}"#)
        }
        return json(200, #"{"data":null,"errors":[{"message":"unknown query"}]}"#)
    }

    /// A canned introspection response describing Query.{me,user(id)}, User{id,name,email}.
    static let introspectionJSON = """
        {"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"types":[
        {"kind":"OBJECT","name":"Query","description":null,"fields":[
          {"name":"me","description":"The current user","args":[],"type":{"kind":"OBJECT","name":"User","ofType":null}},
          {"name":"user","description":"A user by id","args":[{"name":"id","type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"Int","ofType":null}}}],"type":{"kind":"OBJECT","name":"User","ofType":null}}
        ],"inputFields":null,"enumValues":null},
        {"kind":"OBJECT","name":"User","description":"A registered user","fields":[
          {"name":"id","description":null,"args":[],"type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"Int","ofType":null}}},
          {"name":"name","description":null,"args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}},
          {"name":"email","description":"Private email","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}}
        ],"inputFields":null,"enumValues":null},
        {"kind":"SCALAR","name":"Int","description":null,"fields":null,"inputFields":null,"enumValues":null},
        {"kind":"SCALAR","name":"String","description":null,"fields":null,"inputFields":null,"enumValues":null}
        ]}}}
        """
}
