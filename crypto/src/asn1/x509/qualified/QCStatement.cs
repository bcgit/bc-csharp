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
        /// <summary>Return an <see cref="QCStatement"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="QCStatement"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="QCStatement"/>, or null if <paramref name="obj"/> is null.</returns>
        public static QCStatement GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is QCStatement qcStatement)
                return qcStatement;
            return new QCStatement(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="QCStatement"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="QCStatement"/>.</returns>
        public static QCStatement GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new QCStatement(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="QCStatement"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="QCStatement"/>.</returns>
        public static QCStatement GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new QCStatement(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_statementId;
        private readonly Asn1Encodable m_statementInfo;

        private QCStatement(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_statementId = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
            m_statementInfo = Asn1Utilities.ReadOptional(seq, ref pos, element => element);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="QCStatement"/>.</summary>
        /// <param name="qcStatementId">The qc statement id.</param>
        // TODO[api] Rename parameter
        public QCStatement(DerObjectIdentifier qcStatementId)
            : this(qcStatementId, null)
        {
        }

        /// <summary>Create a new <see cref="QCStatement"/>.</summary>
        /// <param name="qcStatementId">The qc statement id.</param>
        /// <param name="qcStatementInfo">The qc statement info.</param>
        // TODO[api] Rename parameters
        public QCStatement(DerObjectIdentifier qcStatementId, Asn1Encodable qcStatementInfo)
        {
            m_statementId = qcStatementId ?? throw new ArgumentNullException(nameof(qcStatementId));
            m_statementInfo = qcStatementInfo;
        }

        /// <summary>Gets the statement id.</summary>
        public DerObjectIdentifier StatementId => m_statementId;

        /// <summary>Gets the statement info.</summary>
        public Asn1Encodable StatementInfo => m_statementInfo;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            return m_statementInfo == null
                ?  new DerSequence(m_statementId)
                :  new DerSequence(m_statementId, m_statementInfo);
        }
    }
}
