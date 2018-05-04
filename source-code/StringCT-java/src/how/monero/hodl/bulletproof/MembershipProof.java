package how.monero.hodl.bulletproof;

import how.monero.hodl.crypto.Curve25519Point;
import how.monero.hodl.crypto.Scalar;

import static how.monero.hodl.crypto.CryptoUtil.getHpnGLookup;
import static how.monero.hodl.crypto.CryptoUtil.hashToScalar;
import static how.monero.hodl.crypto.CryptoUtil.l;
import static how.monero.hodl.crypto.Scalar.randomScalar;
import static how.monero.hodl.util.ByteUtil.concat;

import java.util.Random;

public class MembershipProof {
	
    private static int N = 4;
    private static Scalar scalarN;

    private static Curve25519Point G;
    // private static Curve25519Point H;
    private static Curve25519Point[] Hi;
    private static Curve25519Point[] Yi;
	private static Curve25519Point[] Gi;
    private static Scalar[] ones;
    private static Scalar[] zeros;
    
    static {
    	setN(4);
    }

    public static void setN(int n) {
    	N = n;
        // Set the curve base points
        G = Curve25519Point.G;
        // H = Curve25519Point.hashToPoint(G);
    	ones = new Scalar[N];
    	zeros = new Scalar[N];
		Gi = new Curve25519Point[N];
    	for(int i = 0; i < N; i++) {
    		ones[i] = Scalar.ONE;
    		zeros[i] = Scalar.ZERO;
    	}
    	scalarN = Scalar.intToScalar(N);
        Hi = new Curve25519Point[N];
        for (int i = 0; i < N; i++)
        {
            Hi[i] = getHpnGLookup(2*i+1);
        }
		for(int i = 0; i < N; i++)
			Gi[i] = getHpnGLookup(i+3);
    }
    
    public static class ProofTuple {
    	Curve25519Point B1;
    	Curve25519Point B2;
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
		public ProofTuple(Curve25519Point b1, Curve25519Point b2, Curve25519Point a2, Curve25519Point s1, Curve25519Point s2,
				Curve25519Point t1, Curve25519Point t2, Scalar taux, Scalar mu, Scalar zalpha, Scalar zsk, Scalar t) {
			this.B1 = b1;
			this.B2 = b2;
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
			Scalar seed = hashToScalar(concat(this.B1.toBytes(),this.B2.toBytes()));
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
		
		public byte[] toBytes() {
			byte[] ret = concat(this.B1.toBytes(), this.B2.toBytes(), this.A2.toBytes(), this.S1.toBytes());
			ret = concat(ret, this.S2.toBytes(), this.T1.toBytes(), this.T2.toBytes());
			ret = concat(ret, this.taux.bytes, this.mu.bytes, this.zalpha.bytes);
			ret = concat(ret, this.zsk.bytes, this.t.bytes);
			return ret;
		}
		
		public int size() {
			return this.B1.toBytes().length + this.B2.toBytes().length + this.A2.toBytes().length + this.S1.toBytes().length
					+ this.S2.toBytes().length + this.T1.toBytes().length + this.T2.toBytes().length + this.taux.bytes.length
					+ this.mu.bytes.length + this.zalpha.bytes.length + this.zsk.bytes.length + this.t.bytes.length;
		}
    }
    
    public static class LinearProofTuple extends ProofTuple {
    	Scalar[] l;
    	Scalar[] r;
    	public LinearProofTuple(Curve25519Point b1, Curve25519Point b2, Curve25519Point a2, Curve25519Point s1, Curve25519Point s2,
				Curve25519Point t1, Curve25519Point t2, Scalar taux, Scalar mu, Scalar zalpha, Scalar zsk,
				Scalar[] l, Scalar[] r, Scalar t) {
			super(b1,b2,a2,s1,s2,t1,t2,taux,mu,zalpha,zsk,t);
    		this.l = l;
    		this.r = r;
    	}
    	
    	public int size() {
    		int ret = super.size();
    		for(int i = 0; i < l.length; i++)
    			ret += l[i].bytes.length;
    		for(int i = 0; i < r.length; i++)
    			ret += r[i].bytes.length;
    		return ret;
    	}
    	
    	public byte[] toBytes() {
    		byte[] ret = super.toBytes();
    		for(int i = 0; i < l.length; i++)
    			ret = concat(ret, l[i].bytes);
    		for(int i = 0; i < r.length; i++)
    			ret = concat(ret, r[i].bytes);
    		return ret;
    	}
    }
    
    public static class CompressedProofTuple extends ProofTuple {
    	InnerProductArgument.InnerProductProofTuple innerProductProof;
    	
		public CompressedProofTuple(Curve25519Point b1, Curve25519Point b2, Curve25519Point a2, Curve25519Point s1, Curve25519Point s2,
				Curve25519Point t1, Curve25519Point t2, Scalar taux, Scalar mu, Scalar zalpha, Scalar zsk,
				InnerProductArgument.InnerProductProofTuple innerProductProof, Scalar t) {
			super(b1,b2,a2,s1,s2,t1,t2,taux,mu,zalpha,zsk,t);
			this.innerProductProof = innerProductProof;
		}
		
		public int size() {
			return super.size() + innerProductProof.size();
		}
		
		public byte[] toBytes() {
			return concat(super.toBytes(), innerProductProof.toBytes());
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
    	return hashToScalar(concat(data,(new byte[] {1})));
    }
    public static Scalar H2(byte[] data) {
    	return hashToScalar(concat(data,(new byte[] {2})));
    }
    public static Scalar H3(byte[] data) {
    	return hashToScalar(concat(data,(new byte[] {3})));
    }
    public static Scalar H4(byte[] data) {
    	return hashToScalar(concat(data,(new byte[] {4})));
    }
    public static Scalar H5(byte[] data) {
    	return hashToScalar(concat(data,(new byte[] {5})));
    }
    
    public static Scalar[] ScalarPowerVector(Scalar x) {
    	Scalar[] ret = new Scalar[N];
    	ret[0] = Scalar.ONE;
    	for(int i = 1; i < N; i++)
    		ret[i] = ret[i-1].mul(x);
    	return ret;
    }
    
    public static ProofTuple PROVE(Curve25519Point[] Yip, int istar, Scalar sk, boolean compressed, Scalar seed, byte[] text, Curve25519Point S3) {
    	Curve25519Point[] Yi = new Curve25519Point[N];
       	byte[] yibytes = new byte[] {};
    	for(int i = 0; i < Yip.length; i++) yibytes = concat(yibytes,Yip[i].toBytes());
    	Curve25519Point H = Curve25519Point.hashToPoint(yibytes);
    	for(int i = 0; i < Gi.length; i++) yibytes = concat(yibytes,Gi[i].toBytes());
    	Scalar d = hashToScalar(yibytes);
    	for(int i = 0; i < Yi.length; i++) Yi[i] = Yip[i].add(Gi[i].scalarMultiply(d));
    	
    	// 1. Prepare Index
        Scalar[] bL = InnerProductArgument.VectorScalar(zeros, Scalar.ZERO);
        bL[istar] = Scalar.ONE;
        Scalar[] bR = InnerProductArgument.VectorSubtract(bL, ones);
        
        // 2. Commit 1
        Scalar alpha1 = randomScalar();
        Scalar alpha2 = randomScalar();
        Scalar beta = randomScalar();
        Scalar rho = randomScalar();
        Scalar ralpha = randomScalar();
        Scalar rsk = hashToScalar(seed.bytes);
        
        Scalar[] sL = new Scalar[N];
        Scalar[] sR = new Scalar[N];
        for(int i = 0; i < Yi.length; i++) {
            sL[i] = randomScalar();
            sR[i] = randomScalar();
        }
        Curve25519Point B1 = H.scalarMultiply(alpha1).add(Yip[istar]);
        Curve25519Point B2 = H.scalarMultiply(alpha2).add(Gi[istar]);
        Curve25519Point A2 = H.scalarMultiply(beta).add(CurveVectorExponent(Hi,bR));
        Curve25519Point S1 = H.scalarMultiply(ralpha).add(G.scalarMultiply(rsk));
        Curve25519Point S2 = H.scalarMultiply(rho).add(InnerProductArgument.VectorExponentCustom(Yi,Hi,sL,sR));
        
        // Challenge 1
        byte[] data = B1.toBytes();
        data = concat(data,B2.toBytes());
        data = concat(data,A2.toBytes());
        data = concat(data,S1.toBytes());
        data = concat(data,S2.toBytes());
        for(int i = 0; i < Yi.length; i++)
        	data = concat(concat(data,Yi[i].toBytes()),S3.toBytes());
        
        // Commit 2
        Scalar y = H2(data);
        Scalar z = H3(data);
        Scalar w = H4(data);
        
        Scalar[] yn = ScalarPowerVector(y);
        Scalar t1 = InnerProductArgument.InnerProduct(InnerProductArgument.Hadamard(sR,yn),bL)
        		.sub(InnerProductArgument.InnerProduct(sR,yn).mul(z))
        		.add(InnerProductArgument.InnerProduct(InnerProductArgument.Hadamard(sL,yn),bL).mul(w))
        		.add(InnerProductArgument.InnerProduct(sL,yn).mul(w).mul(z.sub(Scalar.ONE)))
        		.add(InnerProductArgument.InnerProduct(sL,ones).mul(z.sq()));
        Scalar t2 = InnerProductArgument.InnerProduct(InnerProductArgument.Hadamard(sR,yn),sL);
        Scalar tau1 = randomScalar();
        Scalar tau2 = randomScalar();
        Curve25519Point T1 = G.scalarMultiply(t1).add(H.scalarMultiply(tau1));
        Curve25519Point T2 = G.scalarMultiply(t2).add(H.scalarMultiply(tau2));
        
        // Challenge 2
        Scalar x = H1(concat(concat(w.bytes,y.bytes,z.bytes,T1.toBytes()),T2.toBytes(),text));
        
        // Response
        Scalar taux = tau1.mul(x).add(tau2.mul(x.sq()));
        Scalar mu = alpha1.add(alpha2.mul(d)).add(beta.mul(w)).add(rho.mul(x));
        Scalar zalpha1 = ralpha.add(alpha1.mul(x));
        Scalar zsk = rsk.add(sk.mul(x));
        Scalar[] vl = InnerProductArgument.VectorAdd(
        		InnerProductArgument.VectorSubtract(bL,
        			InnerProductArgument.VectorScalar(ones, z)),
        		InnerProductArgument.VectorScalar(sL,x));
        Scalar[] vr = InnerProductArgument.VectorAdd(
        		InnerProductArgument.Hadamard(yn,
	        		InnerProductArgument.VectorAdd(
		        		InnerProductArgument.VectorAdd(
		        				InnerProductArgument.VectorScalar(bR,w),
		        				InnerProductArgument.VectorScalar(ones,w.mul(z))),
		        		InnerProductArgument.VectorScalar(sR,x))),
        		InnerProductArgument.VectorScalar(ones,z.sq()));
        Scalar t = InnerProductArgument.InnerProduct(vl, vr);
        
        if(compressed) {
        	CompressedProofTuple proof = new CompressedProofTuple(B1,B2,A2,S1,S2,T1,T2,taux,mu,zalpha1,zsk,null,t);
			Scalar seed1 = proof.hash();
	        Curve25519Point[] hprime = new Curve25519Point[N];
	        Scalar yinv = new Scalar(y.toBigInteger().modInverse(l));
	        for(int i = 0; i < N; i++)
	        	hprime[i] = Hi[i].scalarMultiply(yinv.pow(i));
			proof.innerProductProof = InnerProductArgument.PROVE(vl,vr,Yi,hprime,seed1);
			return proof;
        }

        return new LinearProofTuple(B1,B2,A2,S1,S2,T1,T2,taux,mu,zalpha1,zsk,vl,vr,t);
    }
    
    public static boolean VERIFY(ProofTuple proof, Curve25519Point[] Yip, byte[] text, Curve25519Point S3) {
    	Curve25519Point[] Yi = new Curve25519Point[N];
       	byte[] yibytes = new byte[] {};
    	for(int i = 0; i < Yip.length; i++) yibytes = concat(yibytes,Yip[i].toBytes());
    	Curve25519Point H = Curve25519Point.hashToPoint(yibytes);
    	for(int i = 0; i < Gi.length; i++) yibytes = concat(yibytes,Gi[i].toBytes());
    	Scalar d = hashToScalar(yibytes);
    	for(int i = 0; i < Yi.length; i++) Yi[i] = Yip[i].add(Gi[i].scalarMultiply(d));
    	
    	byte[] data = proof.B1.toBytes();
        data = concat(data,proof.B2.toBytes());
        data = concat(data,proof.A2.toBytes());
        data = concat(data,proof.S1.toBytes());
        data = concat(data,proof.S2.toBytes());
        for(int i = 0; i < Yi.length; i++)
        	data = concat(concat(data,Yi[i].toBytes()),S3.toBytes());
        
        Scalar y = H2(data);
        Scalar z = H3(data);
        Scalar w = H4(data);
        Scalar x = H1(concat(concat(concat(concat(concat(w.bytes,y.bytes),z.bytes),proof.T1.toBytes()),proof.T2.toBytes()),text));
        Scalar yinv = new Scalar(y.toBigInteger().modInverse(l));
        
        Scalar[] yn = ScalarPowerVector(y);
        Scalar ynsum = InnerProductArgument.InnerProduct(ones,yn);
        Curve25519Point[] hprime = new Curve25519Point[N];
        for(int i = 0; i < N; i++)
        	hprime[i] = Hi[i].scalarMultiply(yinv.pow(i));
    	
    	if(!H.scalarMultiply(proof.zalpha).add(G.scalarMultiply(proof.zsk)).equals(proof.S1.add(proof.B1.scalarMultiply(x))))
    		return false;

        Scalar t0 = z.sq().add(w.mul(z.sub(z.sq())).mul(ynsum)).sub(z.pow(3).mul(scalarN));
    	if(!G.scalarMultiply(proof.t).add(H.scalarMultiply(proof.taux)).equals(
    			G.scalarMultiply(t0)
    			.add(proof.T1.scalarMultiply(x))
    			.add(proof.T2.scalarMultiply(x.sq()))))
    		return false;
    	
    	Curve25519Point P = H.scalarMultiply(Scalar.ZERO.sub(proof.mu))
    			.add(proof.B1).add(proof.B2.scalarMultiply(d)).add(proof.A2.scalarMultiply(w))
    			.add(proof.S2.scalarMultiply(x))
    			.add(InnerProductArgument.VectorExponentCustom(Yi,hprime,
    					InnerProductArgument.VectorScalar(ones,Scalar.ZERO.sub(z)),
    					InnerProductArgument.VectorAdd(
    							InnerProductArgument.VectorScalar(yn,w.mul(z)),
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
    		if(!InnerProductArgument.VERIFY(pi.innerProductProof,P,Yi,hprime,proof.t,seed))
    			return false;
    	} else return false;
    	
    	return true;
    }

	public static void main(String[] args) {
        Curve25519Point S3 = getHpnGLookup(10);
        
        Random rando = new Random();
        byte[] text = new byte[] {0,1,2,3,4,5,6,7};

        int TRIALS = 15;
        for (int count = 0; count < TRIALS; count++)
        {
        	// PKGen
        	int istar = rando.nextInt(N);
        	Yi = new Curve25519Point[N];
        	Scalar sk = randomScalar();
            for (int i = 0; i < N; i++)
            	Yi[i] = G.scalarMultiply(randomScalar());
            Yi[istar] = G.scalarMultiply(sk);
            Scalar seed = randomScalar();

            // Proof
            long t = System.nanoTime();
            LinearProofTuple proof = (LinearProofTuple)PROVE(Yi,istar,sk,false,seed,text,S3);
            long proveTime = System.nanoTime()-t;
            
            t = System.nanoTime();
            if (!VERIFY(proof,Yi,text,S3))
                System.out.println("Test failed");
            else {
            	if(count >= 5)
            		System.out.printf("%d,%d,%d\n", proof.size(),proveTime,System.nanoTime()-t);
            }
        }
        for (int count = 0; count < TRIALS; count++)
        {
        	// PKGen
        	int istar = rando.nextInt(N);
        	Yi = new Curve25519Point[N];
        	Scalar sk = randomScalar();
            for (int i = 0; i < N; i++)
            	Yi[i] = G.scalarMultiply(randomScalar());
            Yi[istar] = G.scalarMultiply(sk);
            Scalar seed = randomScalar();

            // Proof
            long t = System.nanoTime();
            CompressedProofTuple proof = (CompressedProofTuple)PROVE(Yi,istar,sk,true,seed,text,S3);
            long proveTime = System.nanoTime()-t;

            t = System.nanoTime();
            if (!VERIFY(proof,Yi,text,S3))
                System.out.println("Test failed");
            else {
            	if(count >= 5)
            		System.out.printf("%d,%d,%d\n", proof.size(),proveTime,System.nanoTime()-t);
            }
        }
	}

}
