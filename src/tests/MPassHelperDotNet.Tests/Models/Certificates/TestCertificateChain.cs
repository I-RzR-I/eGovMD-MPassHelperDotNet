using System.Security.Cryptography.X509Certificates;

namespace MPassHelperDotNet.Tests.Models.Certificates
{
    internal sealed class TestCertificateChain
    {
        internal TestCertificateChain(X509Certificate2 endEntity, X509Certificate2 intermediate, X509Certificate2 root)
        {
            EndEntity = endEntity;
            Intermediate = intermediate;
            Root = root;
        }

        internal X509Certificate2 EndEntity { get; }

        internal X509Certificate2 Intermediate { get; }

        internal X509Certificate2 Root { get; }
    }
}
