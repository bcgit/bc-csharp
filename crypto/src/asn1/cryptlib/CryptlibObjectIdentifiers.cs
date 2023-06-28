namespace Org.BouncyCastle.Asn1.Cryptlib
{
    internal class CryptlibObjectIdentifiers
    {
        internal static readonly DerObjectIdentifier cryptlib = new DerObjectIdentifier("1.3.6.1.4.1.3029");

        internal static readonly DerObjectIdentifier ecc = cryptlib.Branch("1.5");

        internal static readonly DerObjectIdentifier curvey25519 = ecc.Branch("1");
    }
}
