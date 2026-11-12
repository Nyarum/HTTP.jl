module TimeoutRequest

using ..Connections, ..Streams, ..Exceptions, ..Messages
using ConcurrentUtilities
using ..Exceptions: current_exceptions_to_string
using ..HTTP2: H2Stream

export timeoutlayer

"""
    timeoutlayer(handler) -> handler

Close the `HTTP.Stream` if no data has been received for `readtimeout` seconds.
"""
function timeoutlayer(handler)
    return function timeouts(stream::Union{Stream,H2Stream}; readtimeout::Int=0, logerrors::Bool=false, logtag=nothing, kw...)
        if stream isa H2Stream
            # Never abandon a worker that still owns a native session.
            # The h2 pump closes its socket itself on read timeout.
            return handler(stream; logerrors, logtag, kw...)
        end
        if readtimeout <= 0
            # skip
            return handler(stream; logerrors=logerrors, kw...)
        end
        return try
            try_with_timeout(readtimeout, Response) do timedout
                handler(stream; logerrors=logerrors, logtag=logtag, timedout=timedout, kw...)
            end
        catch e
            if e isa ConcurrentUtilities.TimeoutException
                req = stream.message.request
                req.context[:timeout_errors] = get(req.context, :timeout_errors, 0) + 1
                if logerrors
                    @error current_exceptions_to_string() type=Symbol("HTTP.TimeoutError") method=req.method url=req.url context=req.context timeout=readtimeout logtag=logtag
                end
                e = Exceptions.TimeoutError(readtimeout)
            end
            rethrow(e)
        end
    end
end

end # module TimeoutRequest
