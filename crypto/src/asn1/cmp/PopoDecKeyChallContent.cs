using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class PopoDecKeyChallContent
	    : Asn1Encodable
	{
        public static PopoDecKeyChallContent GetInstance(object obj)
        {
			if (obj is PopoDecKeyChallContent popoDecKeyChallContent)
				return popoDecKeyChallContent;

            if (obj != null)
                return new PopoDecKeyChallContent(Asn1Sequence.GetInstance(obj));

            return null;
        }

        private readonly Asn1Sequence m_content;

	    private PopoDecKeyChallContent(Asn1Sequence seq)
	    {
	        m_content = seq;
	    }

	    public virtual Challenge[] ToChallengeArray()
	    {
			return m_content.MapElements(Challenge.GetInstance);
	    }

	    /**
	     * <pre>
	     * PopoDecKeyChallContent ::= SEQUENCE OF Challenge
	     * </pre>
	     * @return a basic ASN.1 object representation.
	     */
	    public override Asn1Object ToAsn1Object()
	    {
	        return m_content;
	    }
	}
}
