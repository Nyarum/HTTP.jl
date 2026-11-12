module ConnectionReuseTests
using Test, HTTP

# Deterministic transport double: no network, TLS, sleeps or provider credentials.
Base.@kwdef mutable struct ProbeIO <: IO
    open::Bool = true
    incoming::IOBuffer = IOBuffer()
    outgoing::IOBuffer = IOBuffer()
    ended::Bool = false
    fail_headers::Bool = false
end
Base.isopen(io::ProbeIO) = io.open
Base.close(io::ProbeIO) = (io.open = false; nothing)
Base.bytesavailable(io::ProbeIO) = io.open ? bytesavailable(io.incoming) : 0
Base.eof(io::ProbeIO) = !io.open || io.ended
Base.flush(::ProbeIO) = nothing
Base.flush(::HTTP.Connections.Connection{ProbeIO}) = nothing
function Base.unsafe_write(io::ProbeIO, p::Ptr{UInt8}, n::UInt)
    if io.fail_headers
        write(io.outgoing, unsafe_wrap(Vector{UInt8}, p, min(Int(n), 3)))
        throw(Base.IOError("partial header write", Base.UV_EPIPE))
    end
    write(io.outgoing, unsafe_wrap(Vector{UInt8}, p, Int(n)))
end
HTTP.Connections.getconnection(::Type{ProbeIO}, host, port; kw...) = ProbeIO()
request() = HTTP.Request("POST", "/"; url=HTTP.URI("http://example.test/"))
connection(io=ProbeIO()) = HTTP.Connections.Connection(io)
function call_layer(handler, req; pool=HTTP.Pool(1))
    HTTP.ConnectionRequest.connectionlayer(handler)(req; socket_type=ProbeIO,
        pool=pool, proxy=nothing, connect_timeout=0)
end

@testset "Pooling records actual reuse, including forced-new acquisition" begin
    pool = HTTP.Pool(1)
    reused = Ref(false)
    first = HTTP.Connections.newconnection(ProbeIO, "example.test", "80";
        pool, connection_reused=reused, connect_timeout=0)
    @test !reused[]
    HTTP.Connections.releaseconnection(first, true; pool)
    second = HTTP.Connections.newconnection(ProbeIO, "example.test", "80";
        pool, connection_reused=reused, connect_timeout=0)
    @test reused[]
    @test first === second
    HTTP.Connections.releaseconnection(second, true; pool)
    third = HTTP.Connections.newconnection(ProbeIO, "example.test", "80";
        pool, connection_reused=reused, forcenew=true, connect_timeout=0)
    @test !reused[]
    @test third !== first
    HTTP.Connections.releaseconnection(third, false; pool)
    close(first); close(third)
    HTTP.Connections.closeall(pool)
end

@testset "Idle monitor closes EOF and unsolicited data, not a later response" begin
    c = connection(ProbeIO(ended=true))
    HTTP.Connections.monitor_idle_connection(c)
    @test !isopen(c)

    c = connection(ProbeIO(incoming=IOBuffer("unsolicited")))
    HTTP.Connections.monitor_idle_connection(c)
    @test !isopen(c)

    c = connection()
    idle_generation = c.reuse_generation
    @test HTTP.Connections.connection_isvalid(c, 10)
    # Response bytes arrive after checkout; an old idle monitor must not close it.
    c.io.incoming = IOBuffer("HTTP/1.1 200 OK\r\n")
    HTTP.Connections.monitor_idle_connection(c, idle_generation)
    @test isopen(c)
    close(c)

    c = connection()
    c.timestamp = time() - 20
    @test !HTTP.Connections.connection_isvalid(c, 10)
    @test !isopen(c)
end

@testset "Partial header writes never set nothingwritten" begin
    req = request()
    # Simulate flags left by an earlier attempt; connectionlayer must reset them.
    req.context[:nothingwritten] = true
    req.context[:connection_reused] = true
    io = Ref{ProbeIO}()
    @test_throws HTTP.RequestError call_layer((stream; kw...) -> begin
        io[] = stream.stream.io
        io[].fail_headers = true
        HTTP.startwrite(stream)
    end, req)
    @test position(io[].outgoing) > 0
    @test req.context[:request_write_started]
    @test !req.context[:nothingwritten]
    @test !req.context[:connection_reused]
    req.context[:allow_retries] = true
    @test !HTTP.Messages.retryable(req) # non-idempotent POST
end

@testset "Stale checkout is typed and fails before writing any headers" begin
    pool = HTTP.Pool(1)
    seed = request()
    call_layer((stream; kw...) -> stream.message, seed; pool)
    @test !seed.context[:connection_reused]
    req = request()
    io = Ref{ProbeIO}()
    @test_throws HTTP.Exceptions.StaleConnectionError call_layer((stream; kw...) -> begin
        io[] = stream.stream.io
        close(io[]) # peer closure between pool validation and stream preflight
        HTTP.StreamRequest.streamlayer(stream; kw...)
    end, req; pool)
    @test req.context[:connection_reused]
    @test req.context[:nothingwritten]
    @test !req.context[:request_write_started]
    @test position(io[].outgoing) == 0
    HTTP.Connections.closeall(pool)
end
end
