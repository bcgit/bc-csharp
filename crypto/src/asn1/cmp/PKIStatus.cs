using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The values of the PKIStatus type of RFC 4210.</summary>
    public enum PkiStatus
    {
        /// <summary>The request was granted exactly as asked for.</summary>
        Granted = 0,
        /// <summary>The request was granted with modifications.</summary>
        GrantedWithMods = 1,
        /// <summary>The request was rejected.</summary>
        Rejection = 2,
        /// <summary>The request body has not yet been processed; poll to obtain the result.</summary>
        Waiting = 3,
        /// <summary>The request message contained a warning that a revocation is imminent.</summary>
        RevocationWarning = 4,
        /// <summary>A revocation has occurred.</summary>
        RevocationNotification = 5,
        /// <summary>The key has already been updated for the old certificate of the request.</summary>
        KeyUpdateWarning = 6,
    }

    /// <summary>An encodable PKIStatus value.</summary>
    public class PkiStatusEncodable
        : Asn1Encodable
    {
        /// <summary>The status <c>granted</c>.</summary>
        public static readonly PkiStatusEncodable granted = new PkiStatusEncodable(PkiStatus.Granted);
        /// <summary>The status <c>grantedWithMods</c>.</summary>
        public static readonly PkiStatusEncodable grantedWithMods = new PkiStatusEncodable(PkiStatus.GrantedWithMods);
        /// <summary>The status <c>rejection</c>.</summary>
        public static readonly PkiStatusEncodable rejection = new PkiStatusEncodable(PkiStatus.Rejection);
        /// <summary>The status <c>waiting</c>.</summary>
        public static readonly PkiStatusEncodable waiting = new PkiStatusEncodable(PkiStatus.Waiting);
        /// <summary>The status <c>revocationWarning</c>.</summary>
        public static readonly PkiStatusEncodable revocationWarning = new PkiStatusEncodable(PkiStatus.RevocationWarning);
        /// <summary>The status <c>revocationNotification</c>.</summary>
        public static readonly PkiStatusEncodable revocationNotification = new PkiStatusEncodable(PkiStatus.RevocationNotification);
        /// <summary>The status for a key update warning.</summary>
        public static readonly PkiStatusEncodable keyUpdateWaiting = new PkiStatusEncodable(PkiStatus.KeyUpdateWarning);

        /// <summary>Return an <see cref="PkiStatusEncodable"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PkiStatusEncodable"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PkiStatusEncodable"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PkiStatusEncodable GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PkiStatusEncodable pkiStatusEncodable)
                return pkiStatusEncodable;
            return new PkiStatusEncodable(DerInteger.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PkiStatusEncodable"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiStatusEncodable"/>.</returns>
        public static PkiStatusEncodable GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiStatusEncodable(DerInteger.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PkiStatusEncodable"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiStatusEncodable"/>.</returns>
        public static PkiStatusEncodable GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiStatusEncodable(DerInteger.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_status;

        private PkiStatusEncodable(PkiStatus status)
            : this(DerInteger.ValueOf((int)status))
        {
        }

        private PkiStatusEncodable(DerInteger status)
        {
            m_status = status;
        }

        /// <summary>Gets the status.</summary>
        public virtual DerInteger Status => m_status;

        /// <summary>Gets the value.</summary>
        public virtual BigInteger Value => m_status.Value;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_status;
    }
}
