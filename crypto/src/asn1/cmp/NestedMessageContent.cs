namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * NestedMessageContent ::= PKIMessages
     */
    public class NestedMessageContent
        : PkiMessages
    {
        public static new NestedMessageContent GetInstance(object obj)
        {
            if (obj is NestedMessageContent nestedMessageContent)
                return nestedMessageContent;

            if (obj != null)
                return new NestedMessageContent(Asn1Sequence.GetInstance(obj));

            return null;
        }

        public NestedMessageContent(PkiMessage msg)
            : base(msg)
        {
        }

        public NestedMessageContent(PkiMessage[] msgs)
            : base(msgs)
        {
        }

        public NestedMessageContent(Asn1Sequence seq)
            : base(seq)
        {
        }
    }
}
