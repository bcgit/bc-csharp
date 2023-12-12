using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto
{
    /// <summary>Base interface for a PQC signature algorithm.</summary>
    public interface IMessageSigner
    {
        /// <summary>Initialise this instance for signature generation or verification.</summary>
        /// <param name="forSigning">true if we are generating a signature, false otherwise.</param>
        /// <param name="param">parameters for signature generation or verification.</param>
        void Init(bool forSigning, ICipherParameters param);

        // TODO[api]
        //int GetMaxSignatureSize();

        /// <summary>Sign a message.</summary>
        /// <param name="message">the message to be signed.</param>
        /// <returns>the signature of the message.</returns>
        byte[] GenerateSignature(byte[] message);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        // TODO[api]
        //int GenerateSignature(Span<byte> output);
#endif

        /// <summary>Verify a purported signature for a message.</summary>
        /// <param name="message">the message supposedly signed.</param>
        /// <param name="signature">the purported signature to verify.</param>
        /// <returns>true if and only if the signature verified against the message.</returns>
        bool VerifySignature(byte[] message, byte[] signature);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        // TODO[api]
        //bool VerifySignature(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature);
#endif
    }
}
