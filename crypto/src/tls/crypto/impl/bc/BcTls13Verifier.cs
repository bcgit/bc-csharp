using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcTls13Verifier
        : Tls13Verifier
    {
        private readonly SignerSink m_output;

        internal BcTls13Verifier(ISigner verifier)
        {
            m_output = new SignerSink(verifier ?? throw new ArgumentNullException(nameof(verifier)));
        }

        public Stream Stream => m_output;

        public bool VerifySignature(byte[] signature) => m_output.Signer.VerifySignature(signature);
    }
}
