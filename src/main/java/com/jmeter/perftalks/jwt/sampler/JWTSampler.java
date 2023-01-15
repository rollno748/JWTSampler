package com.jmeter.perftalks.jwt.sampler;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;

import org.apache.jmeter.config.Arguments;
import org.apache.jmeter.protocol.java.sampler.AbstractJavaSamplerClient;
import org.apache.jmeter.protocol.java.sampler.JavaSamplerContext;
import org.apache.jmeter.samplers.SampleResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

	
@SuppressWarnings("serial")
public class JWTSampler extends AbstractJavaSamplerClient implements Serializable{

	 private static final String JWT_KEY = "JWT_KEY";
	 private static final String PVT_KEY = "privateKey";
	 private static final String EXP_TIME = "ExpiryTime";	 
	 private static final String USERNAME = "username";
	 private static final String ALGORITHM = "RSA_USING_SHA512";
	 private static final Logger LOGGER = LoggerFactory.getLogger(JWTSampler.class);
	  
	 
	    @Override
	    public Arguments getDefaultParameters() {
	        Arguments defaultParameters = new Arguments();
	        defaultParameters.addArgument(JWT_KEY,"");
	        defaultParameters.addArgument(PVT_KEY,"");
	        defaultParameters.addArgument(EXP_TIME,"3600");
	        defaultParameters.addArgument(USERNAME,"dummyuser123");
	        defaultParameters.addArgument(ALGORITHM, "RSA_USING_SHA512");
	        return defaultParameters;
	    }
	    
	    public SampleResult runTest(JavaSamplerContext javaSamplerContext) {
	    	
	        String jwtKey = javaSamplerContext.getParameter(JWT_KEY);
	        String pvtKey = javaSamplerContext.getParameter(PVT_KEY);
	        String expTime = javaSamplerContext.getParameter(EXP_TIME);
	        String user = javaSamplerContext.getParameter(USERNAME);
	        String algorithm = javaSamplerContext.getParameter(ALGORITHM); 
	        
	        JWTToken token = new JWTToken();
	        
	        SampleResult sampleResult = new SampleResult();
	        sampleResult.sampleStart();
	        try {
	            String message = token.createToken(jwtKey, pvtKey, expTime, user, algorithm);
	            message= "{\"Response\": \""+ message +"\" }";
	            sampleResult.setSuccessful(Boolean.TRUE);
	            sampleResult.setResponseCodeOK();
	            sampleResult.setResponseData(message.toString(), StandardCharsets.UTF_8.name());
	            sampleResult.sampleEnd();
	        } catch (Exception e) {
	            LOGGER.error("Error in processing request",e);
	            sampleResult.sampleEnd();
	            sampleResult.setResponseMessage(e.getMessage());
	            sampleResult.setSuccessful(Boolean.FALSE);
	        }
	        return sampleResult;
	    }
	
}

