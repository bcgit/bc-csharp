using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Ocsp
{
    /**
	 * Carrier for a ResponderID.
	 */
    public class RespID
        : IEquatable<RespID>
    {
        private readonly ResponderID m_id;

		public RespID(ResponderID id)
		{
            m_id = id ?? throw new ArgumentNullException(nameof(id));
		}

		public RespID(X509Name name)
		{
	        m_id = new ResponderID(name);
		}

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
				throw new OcspException("problem creating ID: " + e, e);
			}
		}

		public ResponderID ToAsn1Object() => m_id;

        public bool Equals(RespID other) => this == other || m_id.Equals(other?.m_id);

        public override bool Equals(object obj) => Equals(obj as RespID);

		public override int GetHashCode() => m_id.GetHashCode();
	}
}
