using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Cms
{
    internal class CmsAuthEnvelopedGenerator
    {
        public static readonly DerObjectIdentifier Aes128Ccm = NistObjectIdentifiers.IdAes128Ccm;
        public static readonly DerObjectIdentifier Aes192Ccm = NistObjectIdentifiers.IdAes192Ccm;
        public static readonly DerObjectIdentifier Aes256Ccm = NistObjectIdentifiers.IdAes256Ccm;
        public static readonly DerObjectIdentifier Aes128Gcm = NistObjectIdentifiers.IdAes128Gcm;
        public static readonly DerObjectIdentifier Aes192Gcm = NistObjectIdentifiers.IdAes192Gcm;
        public static readonly DerObjectIdentifier Aes256Gcm = NistObjectIdentifiers.IdAes256Gcm;
        public static readonly DerObjectIdentifier ChaCha20Poly1305 = PkcsObjectIdentifiers.IdAlgAeadChaCha20Poly1305;
    }
}
