package com.jmeter.jwtsampler.sampler;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.apache.commons.codec.binary.Base64;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;

public class GenerateToken {
	
	 public String generate(String jwtKey, String pvtKey, String expTime, String username) throws Exception {
		 
		 long ExpTime = Long.valueOf(expTime);
		 JwtClaims claims = new JwtClaims();
		 claims.setAudience("ysl");
		 claims.setIssuer(jwtKey);
		 claims.setIssuedAtToNow();
		 NumericDate tokenExpDate = NumericDate.now();
		 tokenExpDate.addSeconds(ExpTime);
		 claims.setExpirationTime(tokenExpDate);
		 PrivateKey privateKey = null;
         String JWTToken = null;
		  
		 if ((username != null) && (!username.isEmpty())) {
		      claims.setClaim("guid", username);
		 }
		 
		 try
		    {
		      Security.addProvider(new BouncyCastleProvider());
		      byte[] content = pvtKey.getBytes();
		      
		      String pkcs8Pem = new String(content, StandardCharsets.UTF_8);
		      byte[] pkcs8EncodedBytes = Base64.decodeBase64(pkcs8Pem);
		      KeyFactory factory = KeyFactory.getInstance("RSA");
		      PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
		      privateKey = factory.generatePrivate(privKeySpec);
		    }
		    catch (NoSuchAlgorithmException e){
		      e.printStackTrace();
		    } catch (InvalidKeySpecException e){
		      e.printStackTrace();
		    }
		    
		    JsonWebSignature jws = new JsonWebSignature();
		    jws.setKey(privateKey);
		    jws.setPayload(claims.toJson());
		    jws.setHeader("typ", "JWT");	    
		    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		    
		    //Storing the generated token to the string
		   /* try {
		    	JWTToken = jws.getCompactSerialization();
			} catch (JoseException e) {
				e.printStackTrace();
			}*/
		    
			return jws.getCompactSerialization();
		}
		    
 }
	
