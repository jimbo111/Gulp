import Foundation
import GulpCore
import Testing

@testable import GulpCodec

// F23 §5 (M13b): GraphQL request detection, introspection schema parsing/rendering, and body build.

@Suite("GraphQL (F23 §5)")
struct GraphQLTests {
    func request(_ target: String, body: String, type: String = "application/json") -> RawRequest {
        let head =
            "POST \(target) HTTP/1.1\r\nHost: h\r\nContent-Type: \(type)\r\nContent-Length: \(body.utf8.count)\r\n\r\n"
        return RawRequest(Bytes(head + body))
    }

    @Test("ADV-040: GraphQL requests are detected by path or a JSON query body")
    func test_ADV040_detect() {
        #expect(GraphQL.isGraphQL(request: request("/graphql", body: #"{"query":"{me{id}}"}"#)))
        #expect(GraphQL.isGraphQL(request: request("/api/v2/graphql", body: "{}", type: "text/plain")))
        #expect(GraphQL.isGraphQL(request: request("/query", body: #"{"query":"{ x }"}"#)))
        #expect(!GraphQL.isGraphQL(request: request("/api/users", body: #"{"name":"a"}"#)))
    }

    @Test("ADV-041: a GraphQL request body is parsed and rebuilt")
    func test_ADV041_parseAndBuild() {
        let parsed = GraphQL.parse(
            request: request(
                "/graphql",
                body:
                    #"{"query":"query Q($id:Int){user(id:$id){name}}","variables":{"id":2},"operationName":"Q"}"#
            ))
        let gql = try! #require(parsed)
        #expect(gql.operationName == "Q")
        #expect(gql.query.contains("user(id:$id)"))
        #expect(gql.variablesJSON?.contains("\"id\":2") == true)
        let body = GraphQL.body(gql)
        let rebuilt = try! #require(
            GraphQL.parse(request: request("/graphql", body: String(decoding: body, as: UTF8.self))))
        #expect(rebuilt.query == gql.query && rebuilt.operationName == "Q")
    }

    @Test("ADV-040: an introspection response parses into a schema and renders")
    func test_ADV040_schema() {
        let json = """
            {"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"types":[
            {"kind":"OBJECT","name":"Query","fields":[
              {"name":"user","args":[{"name":"id","type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"Int"}}}],"type":{"kind":"OBJECT","name":"User"}}]},
            {"kind":"OBJECT","name":"Mutation","fields":[{"name":"deleteUser","args":[],"type":{"kind":"SCALAR","name":"Boolean"}}]},
            {"kind":"OBJECT","name":"User","fields":[
              {"name":"id","args":[],"type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"Int"}}},
              {"name":"email","args":[],"type":{"kind":"SCALAR","name":"String"}}]}
            ]}}}
            """
        let schema = try! #require(GraphQLSchema.parse(introspection: Data(json.utf8)))
        #expect(schema.queryType == "Query" && schema.mutationType == "Mutation")
        #expect(schema.queries.map(\.name) == ["user"])
        #expect(schema.queries.first?.args.first.map { "\($0.name): \($0.type)" } == "id: Int!")
        #expect(schema.mutations.map(\.name) == ["deleteUser"])
        #expect(schema.type("User")?.fields.map(\.name) == ["id", "email"])
        let rendered = schema.render()
        #expect(rendered.contains("user(id: Int!): User"))
        #expect(rendered.contains("# mutations"))
        #expect(rendered.contains("email: String"))
    }

    @Test("ADV-040: a disabled-introspection response is recognised")
    func test_ADV040_disabled() {
        let response = RawResponse(
            Bytes(
                "HTTP/1.1 400 X\r\nContent-Length: 48\r\n\r\n{\"errors\":[{\"message\":\"introspection is disabled\"}]}"
            ))
        #expect(GraphQL.introspectionDisabled(response))
        #expect(GraphQLSchema.parse(introspection: Data(#"{"errors":[{"message":"disabled"}]}"#.utf8)) == nil)
    }
}
