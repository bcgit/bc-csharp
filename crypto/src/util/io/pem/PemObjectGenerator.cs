namespace Org.BouncyCastle.Utilities.IO.Pem
{
    /// <summary>Implemented by objects that can generate a <see cref="PemObject"/>.</summary>
    public interface PemObjectGenerator
    {
        /// <returns>
        /// A <see cref="PemObject"/>
        /// </returns>
        /// <exception cref="PemGenerationException"></exception>
        PemObject Generate();
    }
}
