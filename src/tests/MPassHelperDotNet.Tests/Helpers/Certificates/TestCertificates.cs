using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Models.Certificates;

namespace MPassHelperDotNet.Tests.Helpers.Certificates
{
    internal static class TestCertificates
    {
        private static readonly Lazy<X509Certificate2> LazyIdp =
            new Lazy<X509Certificate2>(() => CreateRsa("CN=MPassHelperDotNet Test IdP", 2048), LazyThreadSafetyMode.ExecutionAndPublication);

        private static readonly Lazy<X509Certificate2> LazyIdpRotation =
            new Lazy<X509Certificate2>(() => CreateRsa("CN=MPassHelperDotNet Test IdP Rotation", 2048), LazyThreadSafetyMode.ExecutionAndPublication);

        private static readonly Lazy<X509Certificate2> LazyWrongKey =
            new Lazy<X509Certificate2>(() => CreateRsa("CN=MPassHelperDotNet Test Wrong Key", 2048), LazyThreadSafetyMode.ExecutionAndPublication);

        private static readonly Lazy<X509Certificate2> LazyRsa1024 =
            new Lazy<X509Certificate2>(() => CreateRsa("CN=MPassHelperDotNet Test RSA-1024", 1024), LazyThreadSafetyMode.ExecutionAndPublication);

        private static readonly Lazy<X509Certificate2> LazySp =
            new Lazy<X509Certificate2>(() => CreateRsa("CN=MPassHelperDotNet Test SP", 2048), LazyThreadSafetyMode.ExecutionAndPublication);

        internal static DateTimeOffset DefaultNotBefore => TestClock.Epoch.AddDays(-30);

        internal static DateTimeOffset DefaultNotAfter => TestClock.Epoch.AddDays(730);

        internal static X509Certificate2 Idp => LazyIdp.Value;

        internal static X509Certificate2 IdpRotation => LazyIdpRotation.Value;

        internal static X509Certificate2 WrongKey => LazyWrongKey.Value;

        internal static X509Certificate2 Rsa1024 => LazyRsa1024.Value;

        internal static X509Certificate2 Sp => LazySp.Value;

        internal static X509Certificate2 CreateRsa(string subjectName, int keySize)
            => CreateRsa(subjectName, keySize, DefaultNotBefore, DefaultNotAfter);

        internal static X509Certificate2 CreateRsa(string subjectName, int keySize, DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            var rsa = RSA.Create(keySize);
            var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

            return request.CreateSelfSigned(notBefore, notAfter);
        }

        internal static TestCertificateChain CreateChain(int keySize = 2048)
        {
            var notBefore = DefaultNotBefore;
            var notAfter = DefaultNotAfter;

            var rootKey = RSA.Create(keySize);
            var rootRequest = new CertificateRequest("CN=MPassHelperDotNet Test Root CA", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
            var root = rootRequest.CreateSelfSigned(notBefore, notAfter);

            var intermediateKey = RSA.Create(keySize);
            var intermediateRequest = new CertificateRequest("CN=MPassHelperDotNet Test Intermediate CA", intermediateKey, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            intermediateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(intermediateRequest.PublicKey, false));
            var intermediate = intermediateRequest
                .Create(root, notBefore.AddDays(1), notAfter.AddDays(-1), NewSerialNumber())
                .CopyWithPrivateKey(intermediateKey);

            var endEntityKey = RSA.Create(keySize);
            var endEntityRequest = new CertificateRequest("CN=MPassHelperDotNet Test End Entity", endEntityKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            endEntityRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            endEntityRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            endEntityRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(endEntityRequest.PublicKey, false));
            var endEntity = endEntityRequest
                .Create(intermediate, notBefore.AddDays(2), notAfter.AddDays(-2), NewSerialNumber())
                .CopyWithPrivateKey(endEntityKey);

            return new TestCertificateChain(endEntity, intermediate, root);
        }

        internal static X509Certificate2 PublicOnly(X509Certificate2 certificate)
        {
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadCertificate(certificate.RawData);
#else
            return new X509Certificate2(certificate.RawData);
#endif
        }

        internal static X509Certificate2Collection Collection(params X509Certificate2[] certificates)
        {
            var collection = new X509Certificate2Collection();
            foreach (var certificate in certificates)
                collection.Add(PublicOnly(certificate));

            return collection;
        }

        private static byte[] NewSerialNumber()
        {
            var serial = RandomNumberGenerator.GetBytes(16);
            serial[0] &= 0x7F;
            if (serial[0] == 0)
                serial[0] = 0x01;

            return serial;
        }
    }
}
