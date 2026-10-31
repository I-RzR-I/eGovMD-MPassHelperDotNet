using System.Net;
using System.Net.Sockets;

namespace MPassHelperDotNet.Tests.Helpers.Http
{
    internal static class LoopbackPorts
    {
        internal static int GetFreePort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                return ((IPEndPoint)listener.LocalEndpoint).Port;
            }
            finally
            {
                listener.Stop();
            }
        }
    }
}
