namespace Org.BouncyCastle.Asn1.Smime
{
    /**
     * Handler for creating a vector S/MIME Capabilities
     */
    public class SmimeCapabilityVector
    {
        private readonly Asn1EncodableVector m_capabilities = new Asn1EncodableVector();

        public void AddCapability(DerObjectIdentifier capability) =>
            m_capabilities.Add(DerSequence.FromElement(capability));

        public void AddCapability(DerObjectIdentifier capability, int value) =>
            AddCapability(capability, DerInteger.ValueOf(value));

        public void AddCapability(DerObjectIdentifier capability, Asn1Encodable parameters) =>
            m_capabilities.Add(DerSequence.FromElements(capability, parameters));

        public Asn1EncodableVector ToAsn1EncodableVector() => m_capabilities;
    }
}
