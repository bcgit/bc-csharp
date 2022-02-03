namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    public class KMatrices
    {
        private int nmatrices;
        private int rows;
        private int columns;
        private uint[] data;
        private int matrixPointer;

        public KMatrices(int nmatrices, int rows, int columns, uint[] data)
        {
            this.nmatrices = nmatrices;
            this.rows = rows;
            this.columns = columns;
            this.data = data;
            this.matrixPointer = 0;
        }

        public int GetMatrixPointer()
        {
            return matrixPointer;
        }

        public void SetMatrixPointer(int matrixPointer)
        {
            this.matrixPointer = matrixPointer;
        }

        public int GetNmatrices()
        {
            return nmatrices;
        }

        public int GetSize()
        {
            return rows * columns;
        }

        public int GetRows()
        {
            return rows;
        }

        public int GetColumns()
        {
            return columns;
        }

        public uint[] GetData()
        {
            return data;
        }
    }
}