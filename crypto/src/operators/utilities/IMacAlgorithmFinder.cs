using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Operators.Utilities
{
    public interface IMacAlgorithmFinder
    {
        /// <summary>
        /// Find the MAC algorithm identifier that matches with the passed in MAC name.
        /// </summary>
        /// <param name="macName">the name of the MAC algorithm of interest.</param>
        /// <returns>an algorithm identifier for the MAC name.</returns>
        AlgorithmIdentifier Find(string macName);
    }
}
