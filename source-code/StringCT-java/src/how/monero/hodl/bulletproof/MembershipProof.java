package how.monero.hodl.bulletproof;

import how.monero.hodl.crypto.Curve25519Point;
import how.monero.hodl.crypto.Scalar;

import static how.monero.hodl.crypto.CryptoUtil.hashToScalar;
import static how.monero.hodl.crypto.Scalar.randomScalar;
import static how.monero.hodl.util.ByteUtil.concat;

import java.util.Random;

public class MembershipProof {
	
    private static int N = 64;
    private static Scalar scalarN;

    private static Curve25519Point G;
    private static Curve25519Point H;
    private static Curve25519Point[] Hi;
    private static Curve25519Point[] Yi;
    private static Scalar[] ones;
    private static Scalar[] zeros;
    
    static {
    	ones = new Scalar[N];
    	for(int i = 0; i < N; i++) {
    		ones[i] = Scalar.ONE;
    		zeros[i] = Scalar.ZERO;
    	}
    	scalarN = Scalar.intToScalar(N);
    }
    
    public static class ProofTuple {
    	Curve25519Point A1;
    	Curve25519Point A2;
    	Curve25519Point S1;
    	Curve25519Point S2;
    	Curve25519Point T1;
    	Curve25519Point T2;
    	
    	Scalar taux;
    	Scalar mu;
    	Scalar zalpha;
    	Scalar zsk;
    	
    	Scalar t;
		public ProofTuple(Curve25519Point a1, Curve25519Point a2, Curve25519Point s1, Curve25519Point s2,
				Curve25519Point t1, Curve25519Point t2, Scalar taux, Scalar mu, Scalar zalpha, Scalar zsk, Scalar t) {
			this.A1 = a1;
			this.A2 = a2;
			this.S1 = s1;
			this.S2 = s2;
			this.T1 = t1;
			this.T2 = t2;
			this.taux = taux;
			this.mu = mu;
			this.zalpha = zalpha;
			this.zsk = zsk;
			this.t = t;
		}
		
		public Scalar hash() {
			Scalar seed = hashToScalar(concat(this.A1.toBytes(),this.A2.toBytes()));
			seed = hashToScalar(concat(seed.bytes,this.A2.toBytes()));
			seed = hashToScalar(concat(seed.bytes,this.S1.toBytes()));
			seed = hashToScalar(concat(seed.bytes,this.S2.toBytes()));
			seed = hashToScalar(concat(seed.bytes,this.T1.toBytes()));
			seed = hashToScalar(concat(seed.bytes,this.T2.toBytes()));
			seed = hashToScalar(concat(seed.bytes,this.taux.bytes));
			seed = hashToScalar(concat(seed.bytes,this.mu.bytes));
			seed = hashToScalar(concat(seed.bytes,this.zalpha.bytes));
			seed = hashToScalar(concat(seed.bytes,this.zsk.bytes));
			seed = hashToScalar(concat(seed.bytes,this.t.bytes));
			return seed;
		}
    }
    
    public static class LinearProofTuple extends ProofTuple {
    	Scalar[] l;
    	Scalar[] r;
    	public LinearProofTuple(Curve25519Point a1, Curve25519Point a2, Curve25519Point s1, Curve25519Point s2,
				Curve25519Point t1, Curve25519Point t2, Scalar taux, Scalar mu, Scalar zalpha, Scalar zsk,
				Scalar[] l, Scalar[] r, Scalar t) {
			super(a1,a2,s1,s2,t1,t2,taux,mu,zalpha,zsk,t);
    		this.l = l;
    		this.r = r;
    	}
    }
    
    public static class CompressedProofTuple extends ProofTuple {
    	InnerProductArgument.InnerProductProofTuple innerProductProof;
    	
		public CompressedProofTuple(Curve25519Point a1, Curve25519Point a2, Curve25519Point s1, Curve25519Point s2,
				Curve25519Point t1, Curve25519Point t2, Scalar taux, Scalar mu, Scalar zalpha, Scalar zsk,
				InnerProductArgument.InnerProductProofTuple innerProductProof, Scalar t) {
			super(a1,a2,s1,s2,t1,t2,taux,mu,zalpha,zsk,t);
			this.innerProductProof = innerProductProof;
		}
		
		public static CompressedProofTuple compress(LinearProofTuple proof) {
			Scalar seed = proof.hash();
			InnerProductArgument.InnerProductProofTuple proofTuple = InnerProductArgument.PROVE(proof.l, proof.r, seed);
			return new CompressedProofTuple(
					proof.A1, proof.A2, proof.S1, proof.S2, proof.T1, proof.T2,
					proof.taux, proof.mu, proof.zalpha, proof.zsk, proofTuple, proof.t);
		}
    }
    
    /* Compute a custom vector-scalar commitment */
    public static Curve25519Point CurveVectorExponent(Curve25519Point[] A, Scalar[] a)
    {
        assert a.length == A.length;

        Curve25519Point Result = Curve25519Point.ZERO;
        for (int i = 0; i < a.length; i++)
        {
            Result = Result.add(A[i].scalarMultiply(a[i]));
        }
        return Result;
    }
    
    public static Scalar H1(byte[] data) {
    	return hashToScalar(concat(data,Scalar.ONE.bytes));
    }
    public static Scalar H2(byte[] data) {
    	return hashToScalar(concat(data,Scalar.TWO.bytes));
    }
    public static Scalar H3(byte[] data) {
    	return hashToScalar(concat(data,Scalar.ZERO.bytes));
    }
    public static Scalar H4(byte[] data) {
    	return hashToScalar(concat(data,Scalar.MINUS_ONE.bytes));
    }
    
    public static Scalar[] ScalarPowerVector(Scalar x) {
    	Scalar[] ret = new Scalar[N];
    	ret[0] = Scalar.ONE;
    	for(int i = 1; i < N; i++)
    		ret[i] = ret[i-1].mul(x);
    	return ret;
    }
    
    public static LinearProofTuple PROVE(Curve25519Point[] Yi, int istar, Scalar sk) {
    	Scalar seed = randomScalar();
        // 1. Prepare Index
        Scalar[] bL = InnerProductArgument.VectorScalar(ones, Scalar.ZERO);
        bL[istar] = Scalar.ONE;
        
        Scalar[] bR = InnerProductArgument.VectorSubtract(bL, ones);
        
        Scalar alpha = seed;
        seed = hashToScalar(seed.bytes);
        Scalar beta = seed;
        seed = hashToScalar(seed.bytes);
        Scalar rho = seed;
        seed = hashToScalar(seed.bytes);
        Scalar ralpha = seed;
        seed = hashToScalar(seed.bytes);
        Scalar rsk = seed;
        
        Scalar[] sL = new Scalar[N];
        Scalar[] sR = new Scalar[N];
        for(int i = 0; i < Yi.length; i++) {
            seed = hashToScalar(seed.bytes);
            sL[i] = seed;
            seed = hashToScalar(seed.bytes);
            sR[i] = seed;
        }
        Curve25519Point A1 = H.scalarMultiply(alpha).add(Yi[istar]);
        Curve25519Point A2 = H.scalarMultiply(beta).add(CurveVectorExponent(Hi,bR));
        Curve25519Point S1 = H.scalarMultiply(ralpha).add(G.scalarMultiply(rsk));
        Curve25519Point S2 = H.scalarMultiply(rho).add(InnerProductArgument.VectorExponentCustom(Yi,Hi,sL,sR));
        byte[] data = concat(concat(concat(A1.toBytes(),A2.toBytes()),S1.toBytes()),S2.toBytes());
        for(int i = 0; i < Yi.length; i++)
        	data = concat(data,Yi[i].toBytes());
        Scalar y = H2(data);
        Scalar z = H3(data);
        Scalar w = H4(data);
        Scalar t1 = Scalar.ZERO; // TODO: Compute t1
        Scalar t2 = Scalar.ZERO; // TODO: Compute t2
        seed = hashToScalar(seed.bytes);
        Scalar tau1 = seed;
        seed = hashToScalar(seed.bytes);
        Scalar tau2 = seed;
        Curve25519Point T1 = G.scalarMultiply(t1).add(H.scalarMultiply(tau1));
        Curve25519Point T2 = G.scalarMultiply(t2).add(H.scalarMultiply(tau2));
        Scalar x = H1(concat(concat(concat(concat(w.bytes,y.bytes),z.bytes),T1.toBytes()),T2.toBytes()));
        Scalar taux = tau1.mul(x).add(tau2.mul(x.sq()));
        Scalar mu = alpha.add(beta.mul(w)).add(rho.mul(x));
        Scalar zalpha = ralpha.add(alpha.mul(x));
        Scalar zsk = rsk.add(sk.mul(x));
        Scalar[] l = InnerProductArgument.VectorAdd(InnerProductArgument.VectorSubtract(
        		bL, InnerProductArgument.VectorScalar(ones, z)),InnerProductArgument.VectorScalar(sL,x));
        Scalar[] r = InnerProductArgument.VectorAdd(
        		InnerProductArgument.Hadamard(ScalarPowerVector(y), InnerProductArgument.VectorAdd(
        		InnerProductArgument.VectorAdd(InnerProductArgument.VectorScalar(bR,w),
        		InnerProductArgument.VectorScalar(ones,w.mul(z))),
        		InnerProductArgument.VectorScalar(sR,x))),
        		InnerProductArgument.VectorScalar(ones,z.sq()));
        Scalar t = InnerProductArgument.InnerProduct(l, r);
        return new LinearProofTuple(A1,A2,S1,S2,T1,T2,taux,mu,zalpha,zsk,l,r,t);
    }
    
    public static boolean VERIFY(ProofTuple proof, Curve25519Point[] Yi) {
        byte[] data = concat(concat(concat(proof.A1.toBytes(),proof.A2.toBytes()),proof.S1.toBytes()),proof.S2.toBytes());
        for(int i = 0; i < Yi.length; i++)
        	data = concat(data,Yi[i].toBytes());
        Scalar y = H2(data);
        Scalar z = H3(data);
        Scalar w = H4(data);
        Scalar x = H1(concat(concat(concat(concat(w.bytes,y.bytes),z.bytes),proof.T1.toBytes()),proof.T2.toBytes()));
        Curve25519Point[] hprime = new Curve25519Point[N];
        for(int i = 0; i < N; i++)
        	hprime[i] = Hi[i].scalarMultiply(y.pow(-i));
        
    	if(!G.scalarMultiply(proof.t).add(H.scalarMultiply(proof.taux)).equals(
    			G.scalarMultiply(proof.zalpha.sq().add(w.mul(z.sub(z.sq())).mul(InnerProductArgument.InnerProduct(
    					ones,ScalarPowerVector(y)))).sub(z.pow(3).mul(scalarN))).add(
    					proof.T1.scalarMultiply(x)).add(proof.T2.scalarMultiply(x.sq()))))
    		return false;
    	if(!H.scalarMultiply(proof.zalpha).add(G.scalarMultiply(proof.zsk)).equals(proof.S1.add(proof.A1.scalarMultiply(x))))
    		return false;
    	
    	Curve25519Point P = H.scalarMultiply(Scalar.ZERO.sub(proof.mu)).add(proof.A1).add(proof.A2.scalarMultiply(w)).add(proof.S2.scalarMultiply(x)).add(
				InnerProductArgument.VectorExponentCustom(Yi,hprime,InnerProductArgument.VectorScalar(ones,Scalar.ZERO.sub(z)),
				InnerProductArgument.VectorAdd(InnerProductArgument.VectorScalar(ScalarPowerVector(y),w.mul(z)),
				InnerProductArgument.VectorScalar(ones,z.sq()))));
    	
    	if(proof instanceof LinearProofTuple) {
    		LinearProofTuple pi = (LinearProofTuple) proof;
	    	if(!proof.t.equals(InnerProductArgument.InnerProduct(pi.l, pi.r)))
	    		return false;
	    	if(!InnerProductArgument.VectorExponentCustom(Yi,hprime,pi.l,pi.r).equals(P))
	    		return false;
    	} else if(proof instanceof CompressedProofTuple) {
    		CompressedProofTuple pi = (CompressedProofTuple) proof;
    		Scalar seed = pi.hash();
    		if(!InnerProductArgument.VERIFY(pi.innerProductProof, P, proof.t, seed))
    			return false;
    	} else return false;
    	
    	return true;
    }

	public static void main(String[] args) {

        // Set the curve base points
        G = Curve25519Point.G;
        H = Curve25519Point.hashToPoint(G);
        Hi = new Curve25519Point[N];
        
        Random rando = new Random();

        int TRIALS = 10;
        for (int count = 0; count < TRIALS; count++)
        {
        	// PKGen
        	int istar = rando.nextInt() % N;
        	Yi = new Curve25519Point[N];
        	Scalar sk = randomScalar();
            for (int i = 0; i < N; i++)
            	Yi[i] = G.scalarMultiply(randomScalar());
            Yi[istar] = G.scalarMultiply(sk);

            // Proof
            ProofTuple proof = PROVE(Yi,istar,sk);
            if (!VERIFY(proof,Yi))
                System.out.println("Test failed");
            else
                System.out.println("Test succeeded");
        }
        for (int count = 0; count < TRIALS; count++)
        {
        	// PKGen
        	int istar = rando.nextInt() % N;
        	Yi = new Curve25519Point[N];
        	Scalar sk = randomScalar();
            for (int i = 0; i < N; i++)
            	Yi[i] = G.scalarMultiply(randomScalar());
            Yi[istar] = G.scalarMultiply(sk);

            // Proof
            CompressedProofTuple proof = CompressedProofTuple.compress(PROVE(Yi,istar,sk));
            if (!VERIFY(proof,Yi))
                System.out.println("Test failed");
            else
                System.out.println("Test succeeded");
        }
	}

}
