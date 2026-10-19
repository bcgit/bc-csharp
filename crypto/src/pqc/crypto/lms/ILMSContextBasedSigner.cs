namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    /// <summary>
    /// Interface for LMS signers that work from a context, so the message can be supplied incrementally.
    /// </summary>
    public interface ILmsContextBasedSigner
    {
        /// <summary>Create a context for signing a message.</summary>
        /// <returns>The context.</returns>
        LmsContext GenerateLmsContext();

        /// <summary>Generate a signature from a context into which the message has been written.</summary>
        /// <param name="context">The context.</param>
        /// <returns>The signature.</returns>
        byte[] GenerateSignature(LmsContext context);

        /// <summary>Return the usages remaining.</summary>
        long GetUsagesRemaining();
    }
}