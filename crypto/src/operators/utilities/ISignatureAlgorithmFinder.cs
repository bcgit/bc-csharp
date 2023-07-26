using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Operators.Utilities
{
    public interface ISignatureAlgorithmFinder
    {
        AlgorithmIdentifier Find(string signatureName);
    }
}
