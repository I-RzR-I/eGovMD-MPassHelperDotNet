using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;

namespace WebApplicationSample.Infrastructure
{
    public static class OpaqueKey
    {
        private const int KeyBytes = 32;

        private const int KeyLength = 43;

        public static string Create() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(KeyBytes));

        public static bool IsWellFormed(string? value)
        {
            if (value is null || value.Length != KeyLength)
                return false;

            foreach (var c in value)
            {
                var isBase64Url = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
                if (!isBase64Url)
                    return false;
            }

            return true;
        }
    }
}
