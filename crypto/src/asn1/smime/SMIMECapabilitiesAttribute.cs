using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Smime
{
    /// <summary>The SMIMECapabilities attribute of RFC 8551.</summary>
    public class SmimeCapabilitiesAttribute
        : AttributeX509
    {
        /// <summary>Create a new <see cref="SmimeCapabilitiesAttribute"/>.</summary>
        /// <param name="capabilities">The capabilities.</param>
        public SmimeCapabilitiesAttribute(SmimeCapabilityVector capabilities)
            : base(SmimeAttributes.SmimeCapabilities,
                DerSet.FromElement(DerSequence.FromVector(capabilities.ToAsn1EncodableVector())))
        {
        }
    }
}
