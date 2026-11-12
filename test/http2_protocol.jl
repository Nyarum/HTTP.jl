using Test, HTTP, Sockets

mutable struct PartialH2Write <: IO
    bytes::IOBuffer
end
Base.isopen(io::PartialH2Write) = isopen(io.bytes)
Base.close(io::PartialH2Write) = close(io.bytes)
function Base.unsafe_write(io::PartialH2Write, p::Ptr{UInt8}, n::UInt)
    unsafe_write(io.bytes, p, min(n, UInt(3)))
    throw(Base.IOError("injected partial write", 0))
end

# Minimal wire peers deliberately do not use nghttp2, so both sides cannot agree
# on the same wrapper bug. All streams/servers/tasks are joined in the caller.
function raw_h2_peer(f, bytes; fragment=false)
    server = listen(ip"127.0.0.1", 0)
    port = getsockname(server)[2]
    task = @async begin
        socket = accept(server)
        try
            @test String(read(socket, 24)) == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            if fragment
                for byte in bytes
                    write(socket, byte)
                    yield()
                end
            else
                write(socket, bytes)
            end
            # Wait for client close rather than closing a TCP socket containing
            # unread request data (which would race the response with a TCP RST).
            try read(socket) catch end
        finally
            close(socket)
        end
    end
    try
        f("http://127.0.0.1:$port/")
    finally
        close(server)
        wait(task)
    end
end

h2_frame(type, flags, id, payload=UInt8[]) = vcat(
    UInt8[(length(payload) >> 16) & 0xff, (length(payload) >> 8) & 0xff, length(payload) & 0xff,
          type, flags, (id >> 24) & 0xff, (id >> 16) & 0xff, (id >> 8) & 0xff, id & 0xff], payload)

@testset "HTTP/2 raw wire and pre-write boundaries" begin
    opts = (; http_version=v"2.0", retry=false, redirect=false, proxy=nothing, readtimeout=3)
    settings = h2_frame(4, 0, 0)
    response = vcat(settings, h2_frame(1, 4, 1, UInt8[0x88]), h2_frame(0, 1, 1, collect(codeunits("ok"))))
    raw_h2_peer(response; fragment=true) do url
        r = HTTP.get(url; opts...)
        @test r.status == 200
        @test r.version == v"2.0"
        @test String(r.body) == "ok"
    end
    # NO_ERROR GOAWAY excluding stream 1 proves non-processing at the peer, but
    # this first implementation deliberately does NOT auto-replay even then.
    goaway = vcat(settings, h2_frame(7, 0, 0, zeros(UInt8, 8)))
    raw_h2_peer(goaway) do url
        @test_throws HTTP.HTTP2.HTTP2Error HTTP.post(url, [], "body"; opts...)
    end
    # A zero WINDOW_UPDATE increment is a protocol error, not end-of-body.
    malformed = vcat(settings, h2_frame(8, 0, 0, zeros(UInt8, 4)))
    raw_h2_peer(malformed) do url
        @test_throws HTTP.HTTP2.HTTP2Error HTTP.get(url; opts...)
    end
    req = HTTP.Request("POST", "/", ["Host"=>"example"], "body";
        url=HTTP.URI("https://example/"), version=v"2.0")
    req.context[:allow_retries] = true
    io = PartialH2Write(IOBuffer())
    stream = HTTP.HTTP2.H2Stream(req, io)
    try
        GC.gc()
        @test_throws Base.IOError HTTP.startwrite(stream)
        @test position(io.bytes) == 3
        @test req.context[:request_write_started]
        @test !get(req.context, :nothingwritten, false)
        @test !HTTP.Messages.retryable(req)
    finally
        close(stream)
        HTTP.HTTP2.dispose(stream)
    end
end
