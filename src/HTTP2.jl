module HTTP2

using Sockets, OpenSSL, NetworkOptions, URIs
using nghttp2_jll: libnghttp2
using ..Messages, ..Strings, ..Exceptions
import ..IOExtras

# nghttp2's public, stable C ABI (not its private session/frame layout).
struct FrameHeader
    length::Csize_t
    stream_id::Int32
    type::UInt8
    flags::UInt8
    reserved::UInt8
end
struct GoAway
    hd::FrameHeader
    last_stream_id::Int32
    error_code::UInt32
end
struct NV
    name::Ptr{UInt8}
    value::Ptr{UInt8}
    namelen::Csize_t
    valuelen::Csize_t
    flags::UInt8
end
struct DataProvider
    source::Ptr{Cvoid}
    read_callback::Ptr{Cvoid}
end
struct Setting
    id::Cint
    value::UInt32
end

struct HTTP2Error <: Exceptions.HTTPError
    kind::Symbol
    code::Int
end
Base.showerror(io::IO, e::HTTP2Error) = print(io, "HTTP/2 ", e.kind, " (code ", e.code, ")")
check(n::Integer) = n < 0 ? throw(HTTP2Error(:library, Int(n))) : n

# A session is owned by one request/task. No h1 pool entries, connection
# coalescing, server push, automatic replay, or concurrent stream access.
# close() may be called by another task; it closes only IO, never the C session.
mutable struct H2Stream <: IO
    message::Response
    stream::IO
    session::Ptr{Cvoid}
    id::Int32
    started::Bool
    write_closed::Bool
    headers_ready::Bool
    remote_end::Bool
    closed::Bool
    outgoing::Vector{UInt8}
    outpos::Int
    incoming::Vector{UInt8}
    inpos::Int
    block::Vector{Pair{String,String}}
    header_bytes::Int
    error::Any
    readtimeout::Int
    owner::Task
    deferred::Bool
end

state(p) = unsafe_pointer_to_objref(p)::H2Stream
function failed(s, e)
    s.error === nothing && (s.error = e)
    return Cint(-902) # NGHTTP2_ERR_CALLBACK_FAILURE; never unwind through C
end
function on_header(session, frame, name, namelen, value, valuelen, flags, user)
    s = state(user)
    try
        hd = unsafe_load(Ptr{FrameHeader}(frame))
        hd.stream_id == s.id || return Cint(0)
        s.header_bytes += Int(namelen) + Int(valuelen) + 32
        s.header_bytes <= 65536 || throw(HTTP2Error(:headers_too_large, 0))
        push!(s.block, unsafe_string(name, namelen) => unsafe_string(value, valuelen))
        return Cint(0)
    catch e
        return failed(s, e)
    end
end
function on_data(session, flags, id, data, len, user)
    s = state(user)
    try
        id == s.id || return Cint(0)
        # Manual window updates bound unread data to the default receive window.
        length(s.incoming) - s.inpos + 1 + Int(len) <= 65535 ||
            throw(HTTP2Error(:receive_window, 0))
        append!(s.incoming, unsafe_wrap(Vector{UInt8}, data, Int(len); own=false))
        return Cint(0)
    catch e
        return failed(s, e)
    end
end
function on_frame(session, frame, user)
    s = state(user)
    try
        hd = unsafe_load(Ptr{FrameHeader}(frame))
        if hd.type == 0x07 # GOAWAY; do not replay even REFUSED_STREAM here
            g = unsafe_load(Ptr{GoAway}(frame))
            s.message.request.context[:http2_goaway] = (g.last_stream_id, g.error_code)
            if g.error_code != 0 || g.last_stream_id < s.id
                throw(HTTP2Error(:goaway, Int(g.error_code)))
            end
        elseif hd.stream_id == s.id
            if hd.type == 0x01 # fully decoded HEADERS, including CONTINUATION
                if !s.headers_ready
                    status = [v for (k, v) in s.block if k == ":status"]
                    length(status) == 1 || throw(HTTP2Error(:missing_status, 0))
                    code = tryparse(Int, only(status))
                    code !== nothing && 100 <= code <= 599 || throw(HTTP2Error(:invalid_status, 0))
                    if code >= 200
                        s.message.status = code
                        append!(s.message.headers, (k => v for (k, v) in s.block if !startswith(k, ':')))
                        s.headers_ready = true
                    end
                else
                    s.message.request.context[:http2_trailers] = copy(s.block)
                end
                empty!(s.block)
                # Bound the aggregate as well, including informational responses/trailers.
            end
            if hd.type in (0x00, 0x01) && hd.flags & 0x01 != 0
                s.headers_ready || throw(HTTP2Error(:missing_status, 0))
                s.remote_end = true
            end
        end
        return Cint(0)
    catch e
        return failed(s, e)
    end
end
function on_close(session, id, code, user)
    s = state(user)
    id == s.id || return Cint(0)
    if code != 0 || !s.remote_end
        s.error === nothing && (s.error = HTTP2Error(:stream_closed, Int(code)))
    end
    return Cint(0)
end
function on_invalid_frame(session, frame, code, user)
    return failed(state(user), HTTP2Error(:invalid_frame, Int(code)))
end
function read_data(session, id, buf, len, flags, source, user)
    s = state(user)
    try
        n = min(Int(len), length(s.outgoing) - s.outpos + 1)
        if n > 0
            GC.@preserve s unsafe_copyto!(buf, pointer(s.outgoing, s.outpos), n)
            s.outpos += n
        end
        if s.outpos > length(s.outgoing) && s.write_closed
            unsafe_store!(flags, UInt32(1)) # EOF -> END_STREAM
        elseif n == 0
            s.deferred = true
            return Int(-508) # NGHTTP2_ERR_DEFERRED; resumed by write/closewrite
        end
        return n
    catch e
        failed(s, e)
        return Int(-902)
    end
end

function H2Stream(req::Request, io::IO; readtimeout::Int=0)
    req.response.version = HTTPVersion(2, 0)
    s = H2Stream(req.response, io, C_NULL, 0, false, false, false, false,
                 false, UInt8[], 1, UInt8[], 1, Pair{String,String}[], 0,
                 nothing, readtimeout, current_task(), false)
    callbacks = Ref{Ptr{Cvoid}}(C_NULL)
    option = Ref{Ptr{Cvoid}}(C_NULL)
    session = Ref{Ptr{Cvoid}}(C_NULL)
    try
        check(ccall((:nghttp2_session_callbacks_new, libnghttp2), Cint, (Ref{Ptr{Cvoid}},), callbacks))
        ccall((:nghttp2_session_callbacks_set_on_header_callback, libnghttp2), Cvoid,
              (Ptr{Cvoid}, Ptr{Cvoid}), callbacks[],
              @cfunction(on_header, Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, UInt8, Ptr{Cvoid})))
        ccall((:nghttp2_session_callbacks_set_on_data_chunk_recv_callback, libnghttp2), Cvoid,
              (Ptr{Cvoid}, Ptr{Cvoid}), callbacks[],
              @cfunction(on_data, Cint, (Ptr{Cvoid}, UInt8, Int32, Ptr{UInt8}, Csize_t, Ptr{Cvoid})))
        ccall((:nghttp2_session_callbacks_set_on_frame_recv_callback, libnghttp2), Cvoid,
              (Ptr{Cvoid}, Ptr{Cvoid}), callbacks[],
              @cfunction(on_frame, Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid})))
        ccall((:nghttp2_session_callbacks_set_on_stream_close_callback, libnghttp2), Cvoid,
              (Ptr{Cvoid}, Ptr{Cvoid}), callbacks[],
              @cfunction(on_close, Cint, (Ptr{Cvoid}, Int32, UInt32, Ptr{Cvoid})))
        ccall((:nghttp2_session_callbacks_set_on_invalid_frame_recv_callback, libnghttp2), Cvoid,
              (Ptr{Cvoid}, Ptr{Cvoid}), callbacks[],
              @cfunction(on_invalid_frame, Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Cint, Ptr{Cvoid})))
        check(ccall((:nghttp2_option_new, libnghttp2), Cint, (Ref{Ptr{Cvoid}},), option))
        ccall((:nghttp2_option_set_no_auto_window_update, libnghttp2), Cvoid, (Ptr{Cvoid}, Cint), option[], 1)
        GC.@preserve s check(ccall((:nghttp2_session_client_new2, libnghttp2), Cint,
            (Ref{Ptr{Cvoid}}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            session, callbacks[], pointer_from_objref(s), option[]))
        s.session = session[]
        settings = [Setting(2, 0), Setting(6, 65536)] # disable push; max header list
        GC.@preserve s check(ccall((:nghttp2_submit_settings, libnghttp2), Cint,
            (Ptr{Cvoid}, UInt8, Ptr{Setting}, Csize_t), s.session, 0, settings, length(settings)))
        return s
    catch
        dispose(s)
        rethrow()
    finally
        callbacks[] == C_NULL || ccall((:nghttp2_session_callbacks_del, libnghttp2), Cvoid, (Ptr{Cvoid},), callbacks[])
        option[] == C_NULL || ccall((:nghttp2_option_del, libnghttp2), Cvoid, (Ptr{Cvoid},), option[])
    end
end

function ensure(s)
    s.error === nothing || throw(s.error)
    s.closed && throw(HTTP2Error(:closed, 0))
    current_task() === s.owner || throw(ArgumentError("HTTP/2 stream access must stay in its owning task"))
end
function timedio(f, s)
    timer = s.readtimeout > 0 ? Timer(s.readtimeout) do _
        s.error === nothing && (s.error = Exceptions.TimeoutError(s.readtimeout))
        close(s)
    end : nothing
    try
        result = f()
        s.error === nothing || throw(s.error)
        return result
    catch
        s.error === nothing || throw(s.error)
        rethrow()
    finally
        timer === nothing || close(timer)
    end
end

function flushframes(s)
    ensure(s)
    data = Ref{Ptr{UInt8}}(C_NULL)
    while true
        n = GC.@preserve s ccall((:nghttp2_session_mem_send, libnghttp2), Int,
            (Ptr{Cvoid}, Ref{Ptr{UInt8}}), s.session, data)
        s.error === nothing || throw(s.error)
        check(n)
        n == 0 && break
        # mem_send's memory is valid until the next session call. Copy before
        # writing (which can yield), and mark BEFORE the first transport write.
        chunk = copy(unsafe_wrap(Vector{UInt8}, data[], n; own=false))
        s.message.request.context[:request_write_started] = true
        timedio(s) do
            write(s.stream, chunk)
        end
    end
    return nothing
end
function receiveframes(s)
    ensure(s)
    bytes = timedio(s) do
        first = read!(s.stream, Vector{UInt8}(undef, 1))
        rest = read!(s.stream, Vector{UInt8}(undef, min(bytesavailable(s.stream), 65535)))
        prepend!(rest, first)
    end
    n = GC.@preserve s bytes ccall((:nghttp2_session_mem_recv, libnghttp2), Int,
        (Ptr{Cvoid}, Ptr{UInt8}, Csize_t), s.session, bytes, length(bytes))
    s.error === nothing || throw(s.error)
    check(n)
    n == length(bytes) || throw(HTTP2Error(:incomplete_receive, 0))
    flushframes(s) # SETTINGS/PING acknowledgments, WINDOW_UPDATE, errors
    return nothing
end

function request_headers(req)
    req.method == "CONNECT" && throw(ArgumentError("HTTP/2 CONNECT is not implemented"))
    hasheader(req, "Upgrade") && throw(ArgumentError("HTTP/2 Upgrade is not supported"))
    authority = header(req, "Host")
    headers = Pair{String,String}[":method" => req.method, ":scheme" => req.url.scheme,
                                 ":authority" => authority, ":path" => req.target]
    forbidden = Set(["host", "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"])
    # RFC 9113 8.2.2: also remove all fields nominated by Connection.
    for (k, v) in req.headers
        lowercase(k) == "connection" || continue
        union!(forbidden, lowercase.(strip.(split(v, ','))))
    end
    for (key, value) in req.headers
        k = lowercase(key)
        k in forbidden && continue
        startswith(k, ':') && throw(ArgumentError("User pseudo-headers are not allowed"))
        occursin(r"[\x00\r\n]", k * value) && throw(ArgumentError("Invalid HTTP/2 header"))
        k == "te" && lowercase(strip(value)) != "trailers" && throw(ArgumentError("HTTP/2 TE must be trailers"))
        push!(headers, k => value)
    end
    for (_, value) in headers
        occursin(r"[\x00\r\n]", value) && throw(ArgumentError("Invalid HTTP/2 field value"))
    end
    return headers
end
function IOExtras.startwrite(s::H2Stream)
    ensure(s)
    s.started && return 0
    headers = request_headers(s.message.request)
    # NO_INDEX protects bearer tokens/cookies in the HPACK dynamic table.
    nv = [NV(pointer(k), pointer(v), sizeof(k), sizeof(v),
             UInt8(k in ("authorization", "proxy-authorization", "cookie") ? 1 : 0)) for (k, v) in headers]
    provider = Ref(DataProvider(C_NULL, @cfunction(read_data, Int,
        (Ptr{Cvoid}, Int32, Ptr{UInt8}, Csize_t, Ptr{UInt32}, Ptr{Cvoid}, Ptr{Cvoid}))))
    id = GC.@preserve s headers nv provider ccall((:nghttp2_submit_request, libnghttp2), Int32,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{NV}, Csize_t, Ref{DataProvider}, Ptr{Cvoid}),
        s.session, C_NULL, nv, length(nv), provider, C_NULL)
    check(id)
    s.id = id
    s.started = true
    flushframes(s)
    return 0
end
function resume(s)
    s.deferred || return
    s.deferred = false
    GC.@preserve s check(ccall((:nghttp2_session_resume_data, libnghttp2), Cint,
        (Ptr{Cvoid}, Int32), s.session, s.id))
end
function Base.unsafe_write(s::H2Stream, p::Ptr{UInt8}, n::UInt)
    ensure(s)
    s.write_closed && throw(ArgumentError("HTTP/2 request body is closed"))
    IOExtras.startwrite(s)
    # Split callers' buffers: retain at most one DATA-sized chunk at a time.
    offset = 0
    while offset < n
        count = min(Int(n - offset), 16384)
        s.outgoing = copy(unsafe_wrap(Vector{UInt8}, p + offset, count; own=false))
        s.outpos = 1
        resume(s)
        flushframes(s)
        while s.outpos <= length(s.outgoing)
            s.remote_end && throw(HTTP2Error(:early_response, 0))
            receiveframes(s) # peer's stream/connection send windows may be zero
        end
        offset += count
    end
    s.message.request.context[:nbytes_written] = get(s.message.request.context, :nbytes_written, 0) + Int(n)
    return Int(n)
end
function IOExtras.closewrite(s::H2Stream)
    s.closed && return
    ensure(s)
    s.write_closed && return
    IOExtras.startwrite(s)
    s.write_closed = true
    resume(s)
    flushframes(s)
    return nothing
end
function IOExtras.startread(s::H2Stream)
    IOExtras.closewrite(s)
    while !s.headers_ready
        receiveframes(s)
    end
    return s.message
end
Base.isopen(s::H2Stream) = !s.closed && isopen(s.stream)
Base.isreadable(s::H2Stream) = isopen(s)
Base.iswritable(s::H2Stream) = isopen(s) && !s.write_closed
Base.bytesavailable(s::H2Stream) = length(s.incoming) - s.inpos + 1
function Base.eof(s::H2Stream)
    s.closed && return true
    ensure(s)
    s.headers_ready || IOExtras.startread(s)
    while bytesavailable(s) == 0 && !s.remote_end
        receiveframes(s)
    end
    return bytesavailable(s) == 0 && s.remote_end
end
function consumed(s, n)
    # Called only when the application actually removes bytes, not on receive.
    GC.@preserve s check(ccall((:nghttp2_session_consume, libnghttp2), Cint,
        (Ptr{Cvoid}, Int32, Csize_t), s.session, s.id, n))
    if s.inpos > length(s.incoming)
        empty!(s.incoming)
        s.inpos = 1
    end
    flushframes(s)
end
function Base.readavailable(s::H2Stream)
    eof(s) && return UInt8[]
    out = s.incoming[s.inpos:end]
    s.inpos = length(s.incoming) + 1
    consumed(s, length(out))
    return out
end
function Base.unsafe_read(s::H2Stream, p::Ptr{UInt8}, n::UInt)
    offset = 0
    while offset < n
        eof(s) && throw(EOFError())
        count = min(Int(n - offset), bytesavailable(s))
        GC.@preserve s unsafe_copyto!(p + offset, pointer(s.incoming, s.inpos), count)
        s.inpos += count
        consumed(s, count)
        offset += count
    end
    return nothing
end
Base.read(s::H2Stream, ::Type{UInt8}) = (b = Ref{UInt8}(); GC.@preserve b unsafe_read(s, Base.unsafe_convert(Ptr{UInt8}, b), UInt(1)); b[])
function Base.read(s::H2Stream)
    out = IOBuffer()
    while !eof(s)
        write(out, readavailable(s))
    end
    return take!(out)
end
function IOExtras.closeread(s::H2Stream)
    s.closed && return
    while !eof(s)
        readavailable(s)
    end
    return nothing
end
function Base.close(s::H2Stream)
    s.closed = true
    close(s.stream) # wakes blocked readers/writers; no C calls from cancelling task
    return nothing
end
function dispose(s)
    if s.session != C_NULL
        GC.@preserve s ccall((:nghttp2_session_del, libnghttp2), Cvoid, (Ptr{Cvoid},), s.session)
        s.session = C_NULL
    end
    return nothing
end

function connectio(req; connect_timeout::Int=30, readtimeout::Int=0,
        require_ssl_verification::Bool=NetworkOptions.verify_host(req.url.host, "SSL"),
        sslconfig=nothing, socket_type_tls=nothing, socket_type::Type=TCPSocket, kw...)
    url = req.url
    url.scheme in ("http", "https") || throw(ArgumentError("HTTP/2 requires http or https"))
    socket_type == TCPSocket || throw(ArgumentError("HTTP/2 requires TCPSocket"))
    socket_type_tls in (nothing, OpenSSL.SSLStream) || throw(ArgumentError("HTTP/2 TLS requires OpenSSL"))
    sslconfig === nothing || throw(ArgumentError("Custom HTTP/2 sslconfig is not supported; shared h1 contexts must not be mutated"))
    tcp = TCPSocket()
    io = tcp
    expired = Ref(false)
    timer = connect_timeout > 0 ? Timer(connect_timeout) do _
        expired[] = true
        close(tcp)
    end : nothing
    try
        port = isempty(url.port) ? (url.scheme == "https" ? 443 : 80) : parse(Int, url.port)
        Sockets.connect(tcp, url.host, port)
        if url.scheme == "https"
            ctx = OpenSSL.SSLContext(OpenSSL.TLSClientMethod())
            OpenSSL.ssl_set_min_protocol_version(ctx, OpenSSL.TLS1_2_VERSION)
            OpenSSL.ssl_set_options(ctx, OpenSSL.SSL_OP_NO_COMPRESSION)
            # RFC 9113 9.2: TLS 1.2 AEAD with ephemeral key agreement only.
            # TLS 1.3 cipher suites are configured independently by OpenSSL.
            ccall((:SSL_CTX_set_cipher_list, OpenSSL.libssl), Cint,
                (OpenSSL.SSLContext, Cstring), ctx, "ECDHE+AESGCM:ECDHE+CHACHA20") == 1 || throw(HTTP2Error(:tls_ciphers, 0))
            @static if isdefined(OpenSSL, :ca_chain!)
                ca = get(ENV, "HTTP_CA_BUNDLE", get(ENV, "CURL_CA_BUNDLE", ""))
                isempty(ca) || OpenSSL.ca_chain!(ctx, ca)
            end
            OpenSSL.ssl_set_alpn(ctx, OpenSSL.HTTP2_ALPN)
            io = OpenSSL.SSLStream(ctx, tcp)
            OpenSSL.hostname!(io, url.host)
            OpenSSL.connect(io; require_ssl_verification)
            selected = Ref{Ptr{UInt8}}(C_NULL)
            len = Ref{Cuint}(0)
            ccall((:SSL_get0_alpn_selected, OpenSSL.libssl), Cvoid,
                (OpenSSL.SSL, Ref{Ptr{UInt8}}, Ref{Cuint}), io.ssl, selected, len)
            len[] == 2 && unsafe_string(selected[], len[]) == "h2" || throw(HTTP2Error(:alpn_not_h2, 0))
        end
        expired[] && throw(Exceptions.TimeoutError(connect_timeout))
        req.context[:http2_alpn] = url.scheme == "https" ? "h2" : "prior-knowledge"
        return io
    catch
        close(io)
        expired[] && throw(Exceptions.TimeoutError(connect_timeout))
        rethrow()
    finally
        timer === nothing || close(timer)
    end
end

function connection(handler, req; proxy=nothing, readtimeout::Int=0, kw...)
    proxy === nothing || throw(ArgumentError("HTTP/2 proxy tunnelling is not implemented"))
    req.context[:nothingwritten] = false
    req.context[:request_write_started] = false
    req.context[:connection_reused] = false
    delete!(req.context, :http2_trailers)
    delete!(req.context, :http2_goaway)
    io = try
        connectio(req; readtimeout, kw...)
    catch e
        throw(ConnectError(string(req.url), e))
    end
    s = nothing
    try
        s = H2Stream(req, io; readtimeout)
        return handler(s; readtimeout, kw...)
    catch e
        req.context[:nothingwritten] = !req.context[:request_write_started]
        e isa Exceptions.HTTPError && rethrow()
        throw(RequestError(req, e))
    finally
        try
            close(io)
        finally
            s === nothing || dispose(s)
        end
    end
end

end # module HTTP2
