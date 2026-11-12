# HTTP/2 stream layer. The protocol/session owner stays in this task so that
# timeouts and cancellation cannot leave a worker using a freed native session.
function streamlayer(stream::H2Stream; iofunction=nothing, decompress::Union{Nothing,Bool}=nothing,
        sse_callback=nothing, kw...)::Response
    response = stream.message
    req = response.request
    if sse_callback !== nothing && (iofunction !== nothing || !isbytes(response.body))
        throw(ArgumentError("`sse_callback` cannot be combined with `response_stream` or a custom `iofunction`"))
    end
    startwrite(stream)
    if iofunction !== nothing
        try
            iofunction(stream)
        catch
            close(stream)
            rethrow()
        finally
            if isopen(stream)
                closewrite(stream)
                closeread(stream)
            end
        end
        return response
    end
    # The pump processes both directions during writes, including SETTINGS,
    # early responses and WINDOW_UPDATE; no detached writer task is needed.
    if isbytes(req.body)
        write(stream, req.body)
    else
        writebodystream(stream, req.body)
    end
    closewrite(stream)
    startread(stream)
    decode = decompress === true || (decompress === nothing && lowercase(header(response, "Content-Encoding")) == "gzip")
    body = decode ? GzipDecompressorStream(stream) : stream
    try
        if sse_callback !== nothing && !iserror(response)
            # Match the h1 SSE layer: parse the wire format even when the server
            # omits Content-Type (the Codex Responses endpoint does this).
            callback = event -> applicable(sse_callback, stream, event) ? sse_callback(stream, event) : sse_callback(event)
            req.context[:nbytes] = SSE.parse_stream!(body, callback)
            response.body = UInt8[]
        elseif iserror(response)
            req.context[:response_body] = read(body)
        elseif isbytes(response.body)
            data = read(body)
            if isempty(response.body)
                response.body = data
            else
                length(data) <= length(response.body) || throw(ArgumentError("response buffer too small"))
                copyto!(response.body, 1, data, 1, length(data))
            end
            req.context[:nbytes] = length(data)
        else
            req.context[:nbytes] = write(response.body, body)
        end
        isopen(stream) && closeread(stream)
    finally
        decode && close(body)
    end
    return response
end
