using System;

namespace Org.BouncyCastle.Asn1.X509.Qualified
{
    /**
    * The QCStatement object.
    * <pre>
    * QCStatement ::= SEQUENCE {
    *   statementId        OBJECT IDENTIFIER,
    *   statementInfo      ANY DEFINED BY statementId OPTIONAL}
    * </pre>
    */
    public class QCStatement
        : Asn1Encodable
    {
        public static QCStatement GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is QCStatement qcStatement)
                return qcStatement;
            return new QCStatement(Asn1Sequence.GetInstance(obj));
        }

        public static QCStatement GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new QCStatement(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static QCStatement GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new QCStatement(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_statementId;
        private readonly Asn1Encodable m_statementInfo;

        private QCStatement(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_statementId = DerObjectIdentifier.GetInstance(seq[0]);

			if (seq.Count > 1)
			{
				m_statementInfo = seq[1];
			}
        }

        // TODO[api] Rename parameter
		public QCStatement(DerObjectIdentifier qcStatementId)
            : this(qcStatementId, null)
        {
        }

        // TODO[api] Rename parameters
        public QCStatement(DerObjectIdentifier qcStatementId, Asn1Encodable qcStatementInfo)
        {
            m_statementId = qcStatementId ?? throw new ArgumentNullException(nameof(qcStatementId));
            m_statementInfo = qcStatementInfo;
        }

        public DerObjectIdentifier StatementId => m_statementId;

        public Asn1Encodable StatementInfo => m_statementInfo;

        public override Asn1Object ToAsn1Object()
        {
            return m_statementInfo == null
                ?  new DerSequence(m_statementId)
                :  new DerSequence(m_statementId, m_statementInfo);
        }
    }
}
