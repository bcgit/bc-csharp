using System;

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
            if (obj == null)
                return null;
            if (obj is NestedMessageContent nestedMessageContent)
                return nestedMessageContent;
            if (obj is PkiMessages pkiMessages)
                return new NestedMessageContent(pkiMessages);
#pragma warning disable CS0618 // Type or member is obsolete
            return new NestedMessageContent(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static new NestedMessageContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new NestedMessageContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public NestedMessageContent(PkiMessage msg)
            : base(msg)
        {
        }

        public NestedMessageContent(PkiMessage[] msgs)
            : base(msgs)
        {
        }

        [Obsolete("Use 'GetInstance' instead")]
        public NestedMessageContent(Asn1Sequence seq)
            : base(seq)
        {
        }

        internal NestedMessageContent(PkiMessages other)
            : base(other)
        {
        }
    }
}
