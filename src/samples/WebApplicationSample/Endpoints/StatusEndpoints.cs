using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using MPassHelperDotNet.Abstractions.Services;
using WebApplicationSample.Models;
using HttpResult = Microsoft.AspNetCore.Http.IResult;
using MPassPingResult = RzR.ResultMessage.Abstractions.IResult<MPassHelperDotNet.Models.Client.PingResponse>;

namespace WebApplicationSample.Endpoints
{
    public static class StatusEndpoints
    {
        public static IEndpointRouteBuilder MapStatusEndpoints(this IEndpointRouteBuilder endpoints)
        {
            endpoints.MapGet("/ping", PingAsync).WithName("Ping");

            return endpoints;
        }

        private static async Task<HttpResult> PingAsync(IAuthMPassService authMPassService, CancellationToken cancellationToken)
        {
            MPassPingResult ping = await authMPassService.PingAsync(cancellationToken);

            return Results.Ok(new PingStatusResponse(ping.IsSuccess && ping.Response?.IsSuccess == true));
        }
    }
}
