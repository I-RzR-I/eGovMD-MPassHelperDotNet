using Microsoft.Extensions.Logging;

namespace WebApplicationSample.Infrastructure
{
    public static partial class SampleLog
    {
        [LoggerMessage(EventId = 1, Level = LogLevel.Warning, Message = "MPass {Operation} was rejected: {Reasons}")]
        public static partial void OperationRejected(ILogger logger, string operation, string reasons);

        [LoggerMessage(EventId = 2, Level = LogLevel.Warning, Message = "MPass {Operation} arrived without a pending request")]
        public static partial void PendingRequestMissing(ILogger logger, string operation);

        [LoggerMessage(EventId = 3, Level = LogLevel.Warning, Message = "MPass single logout arrived without an active session")]
        public static partial void SingleLogoutSessionMissing(ILogger logger);

        [LoggerMessage(EventId = 4, Level = LogLevel.Information, Message = "MPass sign-in completed")]
        public static partial void SignedIn(ILogger logger);

        [LoggerMessage(EventId = 5, Level = LogLevel.Information, Message = "MPass session ended by {Initiator}-initiated logout")]
        public static partial void SessionEnded(ILogger logger, string initiator);
    }
}
