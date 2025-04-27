using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Smime
{
    public class SmimeCapabilitiesAttribute
        : AttributeX509
    {
        public SmimeCapabilitiesAttribute(SmimeCapabilityVector capabilities)
            : base(SmimeAttributes.SmimeCapabilities,
                DerSet.FromElement(DerSequence.FromVector(capabilities.ToAsn1EncodableVector())))
        {
        }
    }
}
