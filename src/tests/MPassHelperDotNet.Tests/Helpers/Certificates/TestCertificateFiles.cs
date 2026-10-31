using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MPassHelperDotNet.Tests.Models.Certificates;

namespace MPassHelperDotNet.Tests.Helpers.Certificates
{
    internal sealed class TestCertificateFiles : IDisposable
    {
        private bool _disposed;

        internal TestCertificateFiles()
        {
            DirectoryPath = Path.Combine(Path.GetTempPath(), "MPassHelperDotNet.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(DirectoryPath);
        }

        internal string DirectoryPath { get; }

        internal string WritePfx(X509Certificate2 certificate, string password, string fileName = null)
        {
            var path = NewPath(fileName, ".pfx");
            File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx, password));

            return path;
        }

        internal string WriteCer(X509Certificate2 certificate, string fileName = null)
        {
            var path = NewPath(fileName, ".cer");
            File.WriteAllBytes(path, certificate.RawData);

            return path;
        }

        internal string WritePem(params X509Certificate2[] certificates) => WritePem(null, certificates);

        internal string WritePem(string fileName, IEnumerable<X509Certificate2> certificates)
        {
            var path = NewPath(fileName, ".pem");
            var builder = new StringBuilder();
            foreach (var certificate in certificates)
                builder.Append(ToPem(certificate));

            File.WriteAllText(path, builder.ToString(), new UTF8Encoding(false));

            return path;
        }

        internal string WritePublic(X509Certificate2 certificate, CertificateFileFormat format)
            => format == CertificateFileFormat.Pem ? WritePem(certificate) : WriteCer(certificate);

        internal string WriteText(string fileName, string content)
        {
            var path = NewPath(fileName, ".txt");
            File.WriteAllText(path, content, new UTF8Encoding(false));

            return path;
        }

        internal string MissingPath(string extension = ".cer") => NewPath(null, extension);

        internal static string ToPem(X509Certificate2 certificate)
            => "-----BEGIN CERTIFICATE-----\n" +
               Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks) +
               "\n-----END CERTIFICATE-----\n";

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
            try
            {
                if (Directory.Exists(DirectoryPath))
                    Directory.Delete(DirectoryPath, true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private string NewPath(string fileName, string extension)
        {
            var name = string.IsNullOrEmpty(fileName)
                ? Guid.NewGuid().ToString("N") + extension
                : Path.GetFileName(fileName);

            return Path.Combine(DirectoryPath, name);
        }
    }
}
