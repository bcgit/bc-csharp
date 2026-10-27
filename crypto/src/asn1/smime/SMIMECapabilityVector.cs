namespace Org.BouncyCastle.Asn1.Smime
{
    /**
     * Handler for creating a vector S/MIME Capabilities
     */
    public class SmimeCapabilityVector
    {
        private readonly Asn1EncodableVector m_capabilities = new Asn1EncodableVector();

        /// <summary>Add a capability with no parameters.</summary>
        /// <param name="capability">The object identifier of the capability.</param>
        public void AddCapability(DerObjectIdentifier capability) =>
            m_capabilities.Add(DerSequence.FromElement(capability));

        /// <summary>Add a capability with an integer parameter.</summary>
        /// <param name="capability">The object identifier of the capability.</param>
        /// <param name="value">The parameter value.</param>
        public void AddCapability(DerObjectIdentifier capability, int value) =>
            AddCapability(capability, DerInteger.ValueOf(value));

        /// <summary>Add a capability with parameters.</summary>
        /// <param name="capability">The object identifier of the capability.</param>
        /// <param name="parameters">The parameters.</param>
        public void AddCapability(DerObjectIdentifier capability, Asn1Encodable parameters) =>
            m_capabilities.Add(DerSequence.FromElements(capability, parameters));

        /// <summary>Return the capabilities as a vector.</summary>
        /// <returns>The vector.</returns>
        public Asn1EncodableVector ToAsn1EncodableVector() => m_capabilities;
    }
}
