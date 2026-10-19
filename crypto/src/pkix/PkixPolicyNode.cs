using System.Collections.Generic;
using System.Text;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>A node in the valid policy tree produced by certification path validation (RFC 5280, 6.1).
    /// </summary>
    /// <remarks>
    /// The root of the tree is available from <see cref="PkixCertPathValidatorResult.PolicyTree"/>. Each node holds
    /// a valid policy, the set of policies expected at the next level, any policy qualifiers and a criticality flag.
    /// </remarks>
    public class PkixPolicyNode
    {
        /// <summary>The m children.</summary>
        protected IList<PkixPolicyNode> mChildren;
        /// <summary>The m depth.</summary>
        protected int mDepth;
        /// <summary>The m expected policies.</summary>
        protected ISet<string> mExpectedPolicies;
        /// <summary>The m parent.</summary>
        protected PkixPolicyNode mParent;
        /// <summary>The m policy qualifiers.</summary>
        protected ISet<PolicyQualifierInfo> mPolicyQualifiers;
        /// <summary>The m valid policy.</summary>
        protected string mValidPolicy;
        /// <summary>The m critical.</summary>
        protected bool mCritical;

        /// <summary>Gets the depth of this node in the tree; the root has depth 0.</summary>
        public virtual int Depth
        {
            get { return this.mDepth; }
        }

        /// <summary>Gets the children of this node.</summary>
        public virtual IEnumerable<PkixPolicyNode> Children
        {
            get { return CollectionUtilities.Proxy(mChildren); }
        }

        /// <summary>Gets or sets whether the certificate policies extension behind this node is critical.</summary>
        public virtual bool IsCritical
        {
            get { return this.mCritical; }
            set { this.mCritical = value; }
        }

        /// <summary>Gets a copy of the set of policy qualifiers associated with the valid policy.</summary>
        public virtual ISet<PolicyQualifierInfo> PolicyQualifiers
        {
            get { return new HashSet<PolicyQualifierInfo>(this.mPolicyQualifiers); }
        }

        /// <summary>Gets the object identifier (in string form) of the valid policy of this node.</summary>
        public virtual string ValidPolicy
        {
            get { return this.mValidPolicy; }
        }

        /// <summary>Gets whether this node has any children.</summary>
        public virtual bool HasChildren
        {
            get { return mChildren.Count != 0; }
        }

        /// <summary>Gets or sets (as copies) the policies expected at the next level of the tree.</summary>
        public virtual ISet<string> ExpectedPolicies
        {
            get { return new HashSet<string>(this.mExpectedPolicies); }
            set { this.mExpectedPolicies = new HashSet<string>(value); }
        }

        /// <summary>Gets or sets the parent of this node; null for the root.</summary>
        public virtual PkixPolicyNode Parent
        {
            get { return this.mParent; }
            set { this.mParent = value; }
        }

        /// <summary>Create a policy node.</summary>
        /// <param name="children">The children of the node, or null for none.</param>
        /// <param name="depth">The depth of the node in the tree.</param>
        /// <param name="expectedPolicies">The policies expected at the next level.</param>
        /// <param name="parent">The parent node, or null for the root.</param>
        /// <param name="policyQualifiers">The policy qualifiers associated with the valid policy.</param>
        /// <param name="validPolicy">The object identifier (in string form) of the valid policy.</param>
        /// <param name="critical">Whether the certificate policies extension is critical.</param>
        public PkixPolicyNode(
            IEnumerable<PkixPolicyNode> children,
            int depth,
            ISet<string> expectedPolicies,
            PkixPolicyNode parent,
            ISet<PolicyQualifierInfo> policyQualifiers,
            string validPolicy,
            bool critical)
        {
            mChildren = children == null ? new List<PkixPolicyNode>() : new List<PkixPolicyNode>(children);
            mDepth = depth;
            mExpectedPolicies = expectedPolicies;
            mParent = parent;
            mPolicyQualifiers = policyQualifiers;
            mValidPolicy = validPolicy;
            mCritical = critical;
        }

        /// <summary>Adds a child to this node and makes this node its parent.</summary>
        public virtual void AddChild(PkixPolicyNode child)
        {
            child.Parent = this;
            mChildren.Add(child);
        }

        /// <summary>Returns whether the given policy is one of the expected policies of this node.</summary>
        public virtual bool HasExpectedPolicy(string policy) => mExpectedPolicies.Contains(policy);

        /// <summary>Removes the given child from this node.</summary>
        public virtual void RemoveChild(PkixPolicyNode child) => mChildren.Remove(child);

        /// <summary>Returns a textual representation of the tree rooted at this node.</summary>
        public override string ToString() => ToString("");

        /// <summary>Returns a textual representation of the tree rooted at this node.</summary>
        /// <param name="indent">The indentation to put in front of each line.</param>
        public virtual string ToString(string indent)
        {
            StringBuilder buf = new StringBuilder();
            buf.Append(indent);
            buf.Append(mValidPolicy);
            buf.AppendLine(" {");

            foreach (PkixPolicyNode child in mChildren)
            {
                buf.Append(child.ToString(indent + "    "));
            }

            buf.Append(indent);
            buf.AppendLine("}");
            return buf.ToString();
        }

        /// <summary>Returns a deep copy of the tree rooted at this node.</summary>
        public virtual object Clone() => Copy();

        /// <summary>Returns a deep copy of the tree rooted at this node.</summary>
        public virtual PkixPolicyNode Copy()
        {
            var copy = new PkixPolicyNode(children: null, mDepth, new HashSet<string>(mExpectedPolicies),
                parent: null, new HashSet<PolicyQualifierInfo>(mPolicyQualifiers), mValidPolicy, mCritical);

            foreach (PkixPolicyNode child in mChildren)
            {
                PkixPolicyNode childCopy = child.Copy();
                childCopy.Parent = copy;
                copy.AddChild(childCopy);
            }

            return copy;
        }
    }
}
