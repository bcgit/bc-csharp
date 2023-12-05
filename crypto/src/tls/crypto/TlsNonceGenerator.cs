using System;

namespace Org.BouncyCastle.Tls.Crypto
{
    public interface TlsNonceGenerator
    {
        /// <summary>Generate a nonce byte[] string.</summary>
        /// <param name="size">the length, in bytes, of the nonce to generate.</param>
        /// <returns>the nonce value.</returns>
        byte[] GenerateNonce(int size);

        // TODO[api]
#if false //NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Generate a nonce in a given span.</summary>
        /// <param name="output">the span to generate the nonce into.</param>
        void GenerateNonce(Span<byte> output);
#endif
    }
}
