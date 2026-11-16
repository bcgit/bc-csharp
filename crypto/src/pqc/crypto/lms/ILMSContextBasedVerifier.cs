namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    /// <summary>
    /// Interface for LMS verifiers that work from a context, so the message can be supplied incrementally.
    /// </summary>
    public interface ILmsContextBasedVerifier
    {
        /// <summary>Create a context for verifying a signature.</summary>
        /// <param name="signature">The signature.</param>
        /// <returns>The context.</returns>
        LmsContext GenerateLmsContext(byte[] signature);

        /// <summary>Verify the signature using a context into which the message has been written.</summary>
        /// <param name="context">The context.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        bool Verify(LmsContext context);
    }
}