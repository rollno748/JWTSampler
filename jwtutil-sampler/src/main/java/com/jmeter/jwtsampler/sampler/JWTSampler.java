package com.jmeter.jwtsampler.sampler;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;

import org.apache.jmeter.config.Arguments;
import org.apache.jmeter.protocol.java.sampler.AbstractJavaSamplerClient;
import org.apache.jmeter.protocol.java.sampler.JavaSamplerContext;
import org.apache.jmeter.samplers.SampleResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

	
public class JWTSampler extends AbstractJavaSamplerClient implements Serializable{

	 private static final String JWT_KEY = "JWT_KEY";
	 private static final String ARG1_TAG = "privateKey";
	 private static final String ARG2_TAG = "ExpiryTime";	 
	 private static final String ARG3_TAG = "username";
	 
	 private static final Logger LOGGER = LoggerFactory.getLogger(JWTSampler.class);
	  
	 
	    @Override
	    public Arguments getDefaultParameters() {
	        Arguments defaultParameters = new Arguments();
	        defaultParameters.addArgument(JWT_KEY,"");
	        defaultParameters.addArgument(ARG1_TAG,"");
	        defaultParameters.addArgument(ARG2_TAG,"3600");
	        defaultParameters.addArgument(ARG3_TAG,"dummyuser123");
	        return defaultParameters;
	    }
	    
	    public SampleResult runTest(JavaSamplerContext javaSamplerContext) {
	    	
	        String jwtKey = javaSamplerContext.getParameter(JWT_KEY);
	        String pvtKey = javaSamplerContext.getParameter(ARG1_TAG);
	        String expTime = javaSamplerContext.getParameter(ARG2_TAG);
	        String user = javaSamplerContext.getParameter(ARG3_TAG);
	        
	        
	        GenerateToken generateToken = new GenerateToken();
	        SampleResult sampleResult = new SampleResult();
	        sampleResult.sampleStart();
	        try {
	            String message = generateToken.generate(jwtKey, pvtKey, expTime, user);
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

