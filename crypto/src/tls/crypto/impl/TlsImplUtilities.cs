using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl
{
    /// <summary>Useful utility methods.</summary>
    public abstract class TlsImplUtilities
    {
        /// <summary>Determine whether the connection uses SSL 3.0.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <returns>true if SSL 3.0 is in use, false otherwise.</returns>
        public static bool IsSsl(TlsCryptoParameters cryptoParams)
        {
            return cryptoParams.ServerVersion.IsSsl;
        }

        /// <summary>Determine whether a version (or the version of a connection) is TLS 1.0.</summary>
        /// <param name="version">The version.</param>
        /// <returns>true if it is TLS 1.0, false otherwise.</returns>
        public static bool IsTlsV10(ProtocolVersion version)
        {
            return ProtocolVersion.TLSv10.IsEqualOrEarlierVersionOf(version.GetEquivalentTlsVersion());
        }

        /// <summary>Determine whether a version (or the version of a connection) is TLS 1.0.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <returns>true if it is TLS 1.0, false otherwise.</returns>
        public static bool IsTlsV10(TlsCryptoParameters cryptoParams)
        {
            return IsTlsV10(cryptoParams.ServerVersion);
        }

        /// <summary>Determine whether a version (or the version of a connection) is TLS 1.1.</summary>
        /// <param name="version">The version.</param>
        /// <returns>true if it is TLS 1.1, false otherwise.</returns>
        public static bool IsTlsV11(ProtocolVersion version)
        {
            return ProtocolVersion.TLSv11.IsEqualOrEarlierVersionOf(version.GetEquivalentTlsVersion());
        }

        /// <summary>Determine whether a version (or the version of a connection) is TLS 1.1.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <returns>true if it is TLS 1.1, false otherwise.</returns>
        public static bool IsTlsV11(TlsCryptoParameters cryptoParams)
        {
            return IsTlsV11(cryptoParams.ServerVersion);
        }

        /// <summary>Determine whether a version (or the version of a connection) is TLS 1.2.</summary>
        /// <param name="version">The version.</param>
        /// <returns>true if it is TLS 1.2, false otherwise.</returns>
        public static bool IsTlsV12(ProtocolVersion version)
        {
            return ProtocolVersion.TLSv12.IsEqualOrEarlierVersionOf(version.GetEquivalentTlsVersion());
        }

        /// <summary>Determine whether a version (or the version of a connection) is TLS 1.2.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <returns>true if it is TLS 1.2, false otherwise.</returns>
        public static bool IsTlsV12(TlsCryptoParameters cryptoParams)
        {
            return IsTlsV12(cryptoParams.ServerVersion);
        }

        /// <summary>Determine whether a version (or the version of a connection) is TLS 1.3.</summary>
        /// <param name="version">The version.</param>
        /// <returns>true if it is TLS 1.3, false otherwise.</returns>
        public static bool IsTlsV13(ProtocolVersion version)
        {
            return ProtocolVersion.TLSv13.IsEqualOrEarlierVersionOf(version.GetEquivalentTlsVersion());
        }

        /// <summary>Determine whether a version (or the version of a connection) is TLS 1.3.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <returns>true if it is TLS 1.3, false otherwise.</returns>
        public static bool IsTlsV13(TlsCryptoParameters cryptoParams)
        {
            return IsTlsV13(cryptoParams.ServerVersion);
        }

        /// <summary>Calculate the key block for a connection.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <param name="length">The length of the key block.</param>
        /// <returns>The key block.</returns>
        public static byte[] CalculateKeyBlock(TlsCryptoParameters cryptoParams, int length)
        {
            SecurityParameters securityParameters = cryptoParams.SecurityParameters;
            TlsSecret master_secret = securityParameters.MasterSecret;
            int prfAlgorithm = securityParameters.PrfAlgorithm;
            byte[] seed = Arrays.Concatenate(securityParameters.ServerRandom, securityParameters.ClientRandom);
            return master_secret.DeriveUsingPrf(prfAlgorithm, ExporterLabel.key_expansion, seed, length).Extract();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Calculate the key block for a connection.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <param name="keyBlock">The key block.</param>
        public static void CalculateKeyBlock(TlsCryptoParameters cryptoParams, Span<byte> keyBlock)
        {
            SecurityParameters securityParameters = cryptoParams.SecurityParameters;
            TlsSecret master_secret = securityParameters.MasterSecret;
            int prfAlgorithm = securityParameters.PrfAlgorithm;

            Span<byte> cr = securityParameters.ClientRandom, sr = securityParameters.ServerRandom;
            Span<byte> seed = stackalloc byte[sr.Length + cr.Length];
            sr.CopyTo(seed);
            cr.CopyTo(seed[sr.Length..]);

            TlsSecret derived = master_secret.DeriveUsingPrf(prfAlgorithm, ExporterLabel.key_expansion, seed,
                keyBlock.Length);
            derived.ExtractTo(keyBlock);
        }
#endif
    }
}
