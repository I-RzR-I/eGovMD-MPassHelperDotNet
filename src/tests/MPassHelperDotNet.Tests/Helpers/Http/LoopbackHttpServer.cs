using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MPassHelperDotNet.Tests.Helpers.Http
{
    internal sealed class LoopbackHttpServer : IDisposable
    {
        private const int StartAttempts = 5;

        private readonly CancellationTokenSource _cancellation = new CancellationTokenSource();
        private readonly HttpListener _httpListener;
        private readonly TcpListener _tcpListener;
        private readonly Task _loop;
        private int _requestCount;
        private bool _disposed;

        private LoopbackHttpServer(HttpListener httpListener, TcpListener tcpListener, string baseUrl, HttpStatusCode statusCode)
        {
            _httpListener = httpListener;
            _tcpListener = tcpListener;
            BaseUrl = baseUrl;
            StatusCode = statusCode;
            Mode = httpListener != null ? "HttpListener" : "TcpListener";
            _loop = httpListener != null
                ? Task.Run(() => RunHttpListenerAsync(_cancellation.Token))
                : Task.Run(() => RunTcpListenerAsync(_cancellation.Token));
        }

        internal string BaseUrl { get; }

        internal HttpStatusCode StatusCode { get; }

        internal string Mode { get; }

        internal int RequestCount => Volatile.Read(ref _requestCount);

        internal static LoopbackHttpServer Start(HttpStatusCode statusCode = HttpStatusCode.OK)
        {
            for (var attempt = 0; attempt < StartAttempts; attempt++)
            {
                var port = LoopbackPorts.GetFreePort();
                var listener = new HttpListener();
                listener.Prefixes.Add("http://localhost:" + port + "/");
                try
                {
                    listener.Start();

                    return new LoopbackHttpServer(listener, null, "http://localhost:" + port + "/", statusCode);
                }
                catch (HttpListenerException)
                {
                    listener.Close();
                }
                catch (PlatformNotSupportedException)
                {
                    listener.Close();
                    break;
                }
            }

            var tcpListener = new TcpListener(IPAddress.Loopback, 0);
            tcpListener.Start();
            var tcpPort = ((IPEndPoint)tcpListener.LocalEndpoint).Port;

            return new LoopbackHttpServer(null, tcpListener, "http://127.0.0.1:" + tcpPort + "/", statusCode);
        }

        internal string Url(string path = "saml/login") => BaseUrl + (path ?? string.Empty).TrimStart('/');

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
            _cancellation.Cancel();
            try
            {
                if (_httpListener != null)
                {
                    _httpListener.Stop();
                    _httpListener.Close();
                }

                _tcpListener?.Stop();
            }
            catch (ObjectDisposedException)
            {
            }

            try
            {
                _loop.Wait(TimeSpan.FromSeconds(5));
            }
            catch (AggregateException)
            {
            }

            _cancellation.Dispose();
        }

        private async Task RunHttpListenerAsync(CancellationToken cancellationToken)
        {
            var body = Encoding.ASCII.GetBytes("ok");
            while (!cancellationToken.IsCancellationRequested)
            {
                HttpListenerContext context;
                try
                {
                    context = await _httpListener.GetContextAsync().ConfigureAwait(false);
                }
                catch (HttpListenerException)
                {
                    return;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                catch (InvalidOperationException)
                {
                    return;
                }

                Interlocked.Increment(ref _requestCount);
                try
                {
                    context.Response.StatusCode = (int)StatusCode;
                    context.Response.ContentType = "text/plain";
                    context.Response.ContentLength64 = body.Length;
                    await context.Response.OutputStream.WriteAsync(body, 0, body.Length, cancellationToken).ConfigureAwait(false);
                    context.Response.Close();
                }
                catch (HttpListenerException)
                {
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }

        private async Task RunTcpListenerAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _tcpListener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (SocketException)
                {
                    return;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                catch (InvalidOperationException)
                {
                    return;
                }

                using (client)
                {
                    Interlocked.Increment(ref _requestCount);
                    try
                    {
                        var stream = client.GetStream();
                        await ReadRequestHeadAsync(stream, cancellationToken).ConfigureAwait(false);
                        var head = "HTTP/1.1 " + (int)StatusCode + " " + StatusCode + "\r\n" +
                                   "Content-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                        var bytes = Encoding.ASCII.GetBytes(head);
                        await stream.WriteAsync(bytes, 0, bytes.Length, cancellationToken).ConfigureAwait(false);
                        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch (IOException)
                    {
                    }
                    catch (SocketException)
                    {
                    }
                    catch (ObjectDisposedException)
                    {
                        return;
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                }
            }
        }

        private static async Task ReadRequestHeadAsync(Stream stream, CancellationToken cancellationToken)
        {
            var buffer = new byte[4096];
            var received = new StringBuilder();
            while (received.Length < 65536)
            {
                var read = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    return;

                received.Append(Encoding.ASCII.GetString(buffer, 0, read));
                if (received.ToString().IndexOf("\r\n\r\n", StringComparison.Ordinal) >= 0)
                    return;
            }
        }
    }
}
