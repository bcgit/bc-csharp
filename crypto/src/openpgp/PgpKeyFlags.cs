namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>Key flag values for the KeyFlags subpacket.</remarks>
    public abstract class PgpKeyFlags
    {
        /// <summary>The <c>CanCertify</c> constant, with the value <c>0x01</c>.</summary>
        public const int CanCertify = 0x01; // This key may be used to certify other keys.
        /// <summary>The <c>CanSign</c> constant, with the value <c>0x02</c>.</summary>
        public const int CanSign = 0x02; // This key may be used to sign data.
        /// <summary>The <c>CanEncryptCommunications</c> constant, with the value <c>0x04</c>.</summary>
        public const int CanEncryptCommunications = 0x04; // This key may be used to encrypt communications.
        /// <summary>The <c>CanEncryptStorage</c> constant, with the value <c>0x08</c>.</summary>
        public const int CanEncryptStorage = 0x08; // This key may be used to encrypt storage.
        /// <summary>The <c>MaybeSplit</c> constant, with the value <c>0x10</c>.</summary>
        public const int MaybeSplit = 0x10; // The private component of this key may have been split by a secret-sharing mechanism.
        /// <summary>The <c>MaybeShared</c> constant, with the value <c>0x80</c>.</summary>
        public const int MaybeShared = 0x80; // The private component of this key may be in the possession of more than one person.
    }
}
