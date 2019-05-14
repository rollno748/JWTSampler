package com.jmeter.perftalks.jwt.sampler;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;

public class JWTToken {
	
	private static long expiryTime;
	private static PrivateKey privateKey = null;
	private static byte[] pkcs8EncodedBytes;

	public String createToken(String jwtKey, String pvtKey, String expTime, String username, String JWTAlgorithm) throws JoseException {
		
		expiryTime = Long.valueOf(expTime);
		JwtClaims claims = new JwtClaims();
		
		claims.setAudience("ysl");
		claims.setIssuer(jwtKey);
		claims.setIssuedAtToNow();
		
		NumericDate tokenExpDate = NumericDate.now();
		tokenExpDate.addSeconds(expiryTime);
		claims.setExpirationTime(tokenExpDate);
		

		if ((username != null) && (!username.isEmpty())) {
			claims.setClaim("guid", username);
		}

		try
		{
			Security.addProvider(new BouncyCastleProvider());
			byte[] content = pvtKey.getBytes();

			String pkcs8Pem = new String(content, StandardCharsets.UTF_8);
			pkcs8EncodedBytes = Base64.decodeBase64(pkcs8Pem);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
			privateKey = factory.generatePrivate(privKeySpec);
		}
		catch (NoSuchAlgorithmException e){
			e.printStackTrace();
		} catch (InvalidKeySpecException e){
			e.printStackTrace();
		}

		JsonWebSignature jwsign = new JsonWebSignature();
		jwsign.setKey(privateKey);
		jwsign.setPayload(claims.toJson());
		jwsign.setHeader("typ", "JWT");
		if(JWTAlgorithm == "SHA256") {
			jwsign.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		}else if (JWTAlgorithm == "SHA256") {
			jwsign.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA512);
		}
		

		return jwsign.getCompactSerialization();

	}


}
