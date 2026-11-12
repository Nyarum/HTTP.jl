using Test, HTTP, Sockets

# Standalone: julia --project=. sources/HTTP.jl/test/http2.jl
# Node is a test-only independent peer; no external services or credentials.
@testset "HTTP/2 client (independent Node peer)" begin
    node = Sys.which("node")
    node === nothing && error("HTTP/2 integration tests require Node.js with node:http2")
    peer = Base.open(`$node $(joinpath(@__DIR__, "resources", "http2_peer.mjs"))`, "r")
    try
        ports = parse.(Int, split(readline(peer)))
        base = "http://127.0.0.1:$(ports[1])"
        tls = "https://127.0.0.1:$(ports[2])"
        h1 = "https://127.0.0.1:$(ports[3])"
        opts = (; http_version=v"2.0", retry=false, redirect=false, readtimeout=5, proxy=nothing)
        geth2(path; kw...) = HTTP.get(base * path; opts..., kw...)
        @testset "basic, HPACK, CONTINUATION and headers" begin
            r = geth2("/")
            @test r.version == v"2.0"
            @test r.status == 200
            @test String(r.body) == "ok"
            @test r.request.context[:http2_alpn] == "prior-knowledge"
            @test r.request.context[:connection_reused] === false
            @test r.request.context[:request_write_started] === true
            r = geth2("/largeheaders")
            @test HTTP.header(r, "x-large") == repeat("abcdef", 4000)
            r = geth2("/info")
            @test r.status == 200
            @test !HTTP.hasheader(r, "link")
            @test_throws HTTP.HTTP2.HTTP2Error geth2("/hugeheaders")
            r = HTTP.get(base * "/headers", ["Connection"=>"x-remove", "x-remove"=>"no", "TE"=>"trailers", "X-Visible"=>"yes"]; opts...)
            text = String(r.body)
            @test !occursin("x-remove", text)
            @test !occursin("connection", text)
            @test occursin("x-visible", text)
            @test occursin("trailers", text)
        end
        @testset "flow control and body IO" begin
            data = repeat(UInt8[0x00, 0x01, 0xff, 0x41], 100000)
            r = HTTP.post(base * "/echo", [], data; opts...)
            @test r.body == data
            r = HTTP.post(base * "/echo", [], IOBuffer(data); opts...)
            @test r.body == data
            r = HTTP.post(base * "/echo", [], [data[1:100], data[101:end]]; opts...)
            @test r.body == data
            out = IOBuffer()
            r = geth2("/"; response_stream=out)
            @test String(take!(out)) == "ok"
            @test r.body === out
            r = HTTP.open("POST", base * "/echo", ["Content-Length"=>string(length(data))]; opts...) do s
                @test s isa HTTP.HTTP2.H2Stream
                write(s, data)
                @test HTTP.startread(s).status == 200
                @test read(s, 4) == data[1:4]
                @test read(s) == data[5:end]
            end
            @test r.status == 200
            r = geth2("/trailers")
            @test String(r.body) == "body"
            @test r.request.context[:http2_trailers] == ["x-check"=>"complete"]
            @test String(geth2("/gzip").body) == "compressed response"
        end
        @testset "streaming SSE and callback cancellation" begin
            events = String[]
            r = geth2("/sse"; sse_callback=e->push!(events, e.data))
            @test events == ["one", "two", "three"]
            @test isempty(r.body)
            empty!(events)
            geth2("/sse-gzip"; sse_callback=e->push!(events, e.data))
            @test events == ["one", "two"]
            empty!(events)
            geth2("/sse-untyped"; sse_callback=e->push!(events, e.data))
            @test events == ["one", "two", "three"]
            empty!(events)
            geth2("/sse"; sse_callback=(s, e)->begin push!(events, e.data); close(s) end)
            @test events == ["one"]
        end
        @testset "errors, no replay and timeout" begin
            @test_throws HTTP.StatusError geth2("/error")
            r = geth2("/error"; status_exception=false)
            @test r.status == 429
            @test String(r.body) == "rate limited"
            @test_throws HTTP.HTTP2.HTTP2Error geth2("/reset")
            @test_throws HTTP.HTTP2.HTTP2Error geth2("/goaway")
            @test_throws HTTP.HTTP2.HTTP2Error geth2("/badlength")
            @test_throws HTTP.TimeoutError HTTP.get(base * "/stall"; opts..., readtimeout=1)
            req = HTTP.Request("POST", "/", ["Host"=>"example"], "body";
                url=HTTP.URI("https://example/"), version=v"2.0")
            req.context[:allow_retries] = true
            s = HTTP.HTTP2.H2Stream(req, IOBuffer())
            try
                HTTP.startwrite(s)
                @test req.context[:request_write_started] === true
                @test !get(req.context, :nothingwritten, false)
                @test !HTTP.Messages.retryable(req)
            finally
                close(s)
                HTTP.HTTP2.dispose(s)
            end
        end
        @testset "TLS ALPN must negotiate h2" begin
            r = HTTP.get(tls; opts..., require_ssl_verification=false)
            @test r.version == v"2.0"
            @test r.request.context[:http2_alpn] == "h2"
            @test_throws HTTP.ConnectError HTTP.get(h1; opts..., require_ssl_verification=false)
            @test_throws HTTP.ConnectError HTTP.get(tls; opts..., require_ssl_verification=true)
        end
    finally
        kill(peer)
        wait(peer)
        close(peer)
    end
end

include("http2_protocol.jl")
