using System;
using System.Net;
using System.Net.Sockets;

namespace MPassHelperDotNet.Tests.Helpers.Http
{
    internal sealed class ClosedLoopbackPort : IDisposable
    {
        private readonly Socket _socket;

        internal ClosedLoopbackPort()
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            Port = ((IPEndPoint)_socket.LocalEndPoint).Port;
        }

        internal int Port { get; }

        internal string Url(string path = "saml/login") => "http://127.0.0.1:" + Port + "/" + (path ?? string.Empty).TrimStart('/');

        public void Dispose() => _socket.Dispose();
    }
}
