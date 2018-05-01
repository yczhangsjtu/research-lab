package test.how.monero.hodl;

import java.math.BigInteger;
import java.util.Date;

import com.yczhang.monero.bulletct.SpendParams;
import com.yczhang.monero.bulletct.BulletRingCT.KeyGenResult;
import com.yczhang.monero.bulletct.BulletRingCT.SK;
import com.yczhang.monero.bulletct.BulletRingCT.SpendSignature;

import how.monero.hodl.bulletproof.InnerProductArgument;
import how.monero.hodl.bulletproof.MembershipProof;
import how.monero.hodl.crypto.Curve25519Point;
import how.monero.hodl.crypto.Curve25519PointPair;
import how.monero.hodl.crypto.Scalar;

import static com.yczhang.monero.bulletct.BulletRingCT.KEYGEN;
import static com.yczhang.monero.bulletct.BulletRingCT.SPEND;
import static com.yczhang.monero.bulletct.BulletRingCT.VERIFY;

public class BulletRingCTSpendTest {

	public static SpendParams createTestSpendParams(int ringSize, int inputs) {

	    SpendParams sp = new SpendParams();
	    KeyGenResult[] realInputs = new KeyGenResult[inputs];
	    for(int i=0; i<inputs; i++) realInputs[i] = KEYGEN();
	    
	    KeyGenResult[] outputs = new KeyGenResult[2];
	    outputs[0] = KEYGEN(realInputs[0].sk.m.toBigInteger().divide(BigInteger.valueOf(2)));
	    Scalar sum = realInputs[0].sk.m;
	    for(int i = 1; i < inputs; i++) sum = sum.add(realInputs[i].sk.m);
	    outputs[1] = KEYGEN(sum.sub(outputs[0].sk.m));
	    
	    sp.iAsterisk = (int) Math.floor(Math.random()*ringSize); // the ring index of the sender's owned inputs

	    sp.pk = new Curve25519PointPair[inputs][ringSize];

	    sp.sk = new SK[inputs];
	    for(int j=0; j<inputs; j++) {
	    	for(int i=0; i<ringSize; i++) {
	    		sp.pk[j][i] = (i==sp.iAsterisk) ? realInputs[j].pk : KEYGEN().pk;
	    	}
	    	sp.sk[j] = realInputs[j].sk;
	    }
	    
	    sp.output = new Scalar[outputs.length];
	    sp.out = new Curve25519Point[outputs.length];
	    for(int i = 0; i < sp.output.length; i++) {
	    	sp.output[i] = outputs[i].sk.m;
	    	sp.out[i] = outputs[i].pk.P1;
	    }
	    
	    return sp;
	}
	
	public static void spendTest() {
	    boolean pauseAtEachStage = false;
	    int testIterations = 1;
	    int[] candinputs = new int[] {1,1,2,3,4,5,10,20};
	    int[] candringsize = new int[] {4,8,16,32,64,128,256,512,1024};
	    String summary = "";

	    for(int count = 0; count < candinputs.length; count++) {
	    	for(int count2 = 0; count2 < candringsize.length; count2++) {
	    		int inputs = candinputs[count];
	    		int ringSize = candringsize[count2];
	    		System.out.printf("Start testing for inputs = %d and ringSize = %d\n",inputs,ringSize);
	    		MembershipProof.setN(ringSize);
	    		InnerProductArgument.setN(ringSize);
	    		
	    		long startMs = new Date().getTime();
	    		SpendParams[] sp = new SpendParams[testIterations];

	    		for (int i=0; i<testIterations; i++) sp[i] = createTestSpendParams(ringSize, inputs);
	    		System.out.println("Spend params generation duration: " + (new Date().getTime()-startMs) + " ms");

	    		if(pauseAtEachStage) { System.out.println("Press enter to continue"); try { System.in.read(); } catch (Exception e) {}; System.out.println("Continuing..."); }

	    		Curve25519Point.scalarMults = 0;
	    		Curve25519Point.scalarBaseMults = 0;

	    		startMs = new Date().getTime();

	    		SpendSignature[] spendSignature = new SpendSignature[testIterations];
	    		for (int i=0; i<testIterations; i++) {
	    			spendSignature[i] = SPEND(sp[i]);
	    		}

	    		long siggentime = new Date().getTime()-startMs;
	    		System.out.println("Spend signature generation duration: " + siggentime + " ms");

	    		byte[][] spendSignatureBytes = new byte[testIterations][];
	    		for (int i=0; i<testIterations; i++) {
	    			spendSignatureBytes[i] = spendSignature[i].toBytes();
	    			System.out.println("Spend Signature length (bytes):" + spendSignatureBytes[i].length);
	    		}

	    		if(pauseAtEachStage) { System.out.println("Press enter to continue"); try { System.in.read(); } catch (Exception e) {}; System.out.println("Continuing..."); }
	    		startMs = new Date().getTime();

	    		int spendScalarMults = Curve25519Point.scalarMults;
	    		int spendScalarBaseMults = Curve25519Point.scalarBaseMults;
	    		System.out.println("Spend ScalarMults: " + Curve25519Point.scalarMults);
	    		System.out.println("Spend BaseScalarMults: " + Curve25519Point.scalarBaseMults);
	    		Curve25519Point.scalarMults = 0;
	    		Curve25519Point.scalarBaseMults = 0;

	    		//Ed25519GroupElement.enableLineRecording = true;
	    		Curve25519Point.lineRecordingSourceFile = "StringCT.java";

	    		// verify the spend transaction
	    		for (int i=0; i<testIterations; i++) {
	    			boolean verified = VERIFY(sp[i].pk, spendSignature[i]);
	    			System.out.println("verified: " + verified);
	    		}

	    		System.out.println("Verify ScalarMults: " + Curve25519Point.scalarMults);
	    		System.out.println("Verify BaseScalarMults: " + Curve25519Point.scalarBaseMults);

	    		long verifytime = new Date().getTime()-startMs;
	    		System.out.println("Signature verification duration: " + verifytime + " ms");

	    		summary += String.format("%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", inputs, 2, ringSize, siggentime,
	    				spendSignatureBytes[0].length, spendScalarMults, spendScalarBaseMults,
	    				verifytime, Curve25519Point.scalarMults, Curve25519Point.scalarBaseMults);
	    	}
	    }
	    System.out.println(summary);
	}

	public static void main(String[] args) {
	    long startTime = new Date().getTime();
	    spendTest();
	    System.out.println("Total duration: " + (new Date().getTime()-startTime) + " ms");
	}

}
