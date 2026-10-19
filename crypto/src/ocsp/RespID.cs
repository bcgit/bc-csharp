using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Ocsp
{
    /// <summary>Carrier for a ResponderID.</summary>
    public class RespID
        : IEquatable<RespID>
    {
        private readonly ResponderID m_id;

        /// <summary>Create from an existing ASN.1 ResponderID structure.</summary>
        /// <param name="id">The ASN.1 structure.</param>
        /// <exception cref="ArgumentNullException"><paramref name="id"/> is null.</exception>
        public RespID(ResponderID id)
        {
            m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

        /// <summary>Create an ID that identifies the responder by name.</summary>
        /// <param name="name">The distinguished name of the responder.</param>
        public RespID(X509Name name)
        {
            m_id = new ResponderID(name);
        }

        /// <summary>Create an ID that identifies the responder by the SHA-1 hash of its public key.</summary>
        /// <param name="publicKey">The responder's public key.</param>
        /// <exception cref="OcspException">The key hash could not be calculated.</exception>
        public RespID(AsymmetricKeyParameter publicKey)
        {
            try
            {
                SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
                byte[] key = info.PublicKey.GetBytes();
                byte[] keyHash = DigestUtilities.CalculateDigest("SHA1", key);

                m_id = new ResponderID(new DerOctetString(keyHash));
            }
            catch (Exception e)
            {
                throw new OcspException("problem creating ID", e);
            }
        }

        /// <summary>Return the underlying ASN.1 structure.</summary>
        public ResponderID ToAsn1Object() => m_id;

        public bool Equals(RespID other) => this == other || m_id.Equals(other?.m_id);

        public override bool Equals(object obj) => Equals(obj as RespID);

        public override int GetHashCode() => m_id.GetHashCode();
    }
}
