using System;

using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crmf
{
    internal static class PKMacValueGenerator
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static PKMacValue Generate(PKMacBuilder builder, ReadOnlySpan<char> password,
            SubjectPublicKeyInfo keyInfo)
        {
            var macFactory = builder.Build(password);
            var macValue = X509Utilities.GenerateMac(macFactory, keyInfo);
            return new PKMacValue((AlgorithmIdentifier)macFactory.AlgorithmDetails, macValue);
        }
#else
        internal static PKMacValue Generate(PKMacBuilder builder, char[] password, SubjectPublicKeyInfo keyInfo)
        {
            var macFactory = builder.Build(password);
            var macValue = X509Utilities.GenerateMac(macFactory, keyInfo);
            return new PKMacValue((AlgorithmIdentifier)macFactory.AlgorithmDetails, macValue);
        }
#endif
    }
}
