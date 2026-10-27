using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Operators
{
    /// <summary>Builder for the content encryptors used when creating CMS messages.</summary>
    public class CmsContentEncryptorBuilder
    {
        private readonly SecureRandom m_random;
        private readonly DerObjectIdentifier m_encryptionOid;
        private readonly int m_keySize;

        /// <summary>Create a new <see cref="CmsContentEncryptorBuilder"/>.</summary>
        /// <param name="encryptionOID">The encryption OID.</param>
        public CmsContentEncryptorBuilder(DerObjectIdentifier encryptionOID)
            : this(random: null, encryptionOID)
        {
        }

        /// <summary>Create a new <see cref="CmsContentEncryptorBuilder"/>.</summary>
        /// <param name="encryptionOID">The encryption OID.</param>
        /// <param name="keySize">The key size in bits.</param>
        public CmsContentEncryptorBuilder(DerObjectIdentifier encryptionOID, int keySize)
            : this(random: null, encryptionOID, keySize)
        {
        }

        /// <summary>Create a new <see cref="CmsContentEncryptorBuilder"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        /// <param name="encryptionOid">The encryption oid.</param>
        public CmsContentEncryptorBuilder(SecureRandom random, DerObjectIdentifier encryptionOid)
            : this(random, encryptionOid, -1)
        {
        }

        /// <summary>Create a new <see cref="CmsContentEncryptorBuilder"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        /// <param name="encryptionOid">The encryption oid.</param>
        /// <param name="keySize">The key size in bits.</param>
        public CmsContentEncryptorBuilder(SecureRandom random, DerObjectIdentifier encryptionOid, int keySize)
        {
            m_random = random;
            m_encryptionOid = encryptionOid;
            m_keySize = keySize;
        }

        /// <summary>Build a cipher builder with a freshly generated key.</summary>
        /// <returns>The cipher builder.</returns>
        public ICipherBuilderWithKey Build() => new Asn1CipherBuilderWithKey(m_encryptionOid, m_keySize, m_random);
    }
}
