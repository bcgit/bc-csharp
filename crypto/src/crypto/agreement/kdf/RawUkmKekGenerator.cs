using System;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Agreement.Kdf
{
    /// <summary>
    /// X9.63 based key derivation function for ECDH CMS, with the user keying material itself as the SharedInfo.
    /// </summary>
    /// <remarks>
    /// NOT conformant: RFC 5753 sec. 7.2 requires the DER-encoded ECC-CMS-SharedInfo (see
    /// <see cref="ECDHKekGenerator"/>). Used only to read messages from senders that did this instead, among them
    /// bc-java 1.53 to 1.86 for 1-Pass ECMQV, where the user keying material is the addedukm, or absent.
    /// </remarks>
    internal sealed class RawUkmKekGenerator
        : IDerivationFunction
    {
        private readonly IDerivationFunction m_kdf;

        internal RawUkmKekGenerator(IDigest digest)
        {
            m_kdf = new Kdf2BytesGenerator(digest);
        }

        public void Init(IDerivationParameters param)
        {
            var parameters = (DHKdfParameters)param ?? throw new ArgumentNullException(nameof(param));

            m_kdf.Init(new KdfParameters(parameters.Z, parameters.ExtraInfo));
        }

        public IDigest Digest => m_kdf.Digest;

        public int GenerateBytes(byte[] outBytes, int outOff, int length) =>
            m_kdf.GenerateBytes(outBytes, outOff, length);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int GenerateBytes(Span<byte> output) => m_kdf.GenerateBytes(output);
#endif
    }
}
